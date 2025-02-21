// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package valkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/errwrap"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/mediocregopher/radix/v4"
	"github.com/mediocregopher/radix/v4/resp/resp3"
	dbplugin "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/openbao/openbao/sdk/v2/database/helper/credsutil"
)

const (
	valkeyTypeName        = "valkey"
	defaultValkeyUserRule = `["~*", "+@read"]`
	defaultTimeout        = 20000 * time.Millisecond
	maxKeyLength          = 64
)

var _ dbplugin.Database = &ValkeyDB{}

// Type that combines the custom plugins Valkey database connection configuration options and the Vault CredentialsProducer
// used for generating user information for the Valkey database.
type ValkeyDB struct {
	*valkeyDBConnectionProducer
	credsutil.CredentialsProducer
}

// New implements builtinplugins.BuiltinFactory
func New() (interface{}, error) {
	db := new()
	// Wrap the plugin with middleware to sanitize errors
	dbType := dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues)
	return dbType, nil
}

func new() *ValkeyDB {
	connProducer := &valkeyDBConnectionProducer{}
	connProducer.Type = valkeyTypeName

	db := &ValkeyDB{
		valkeyDBConnectionProducer: connProducer,
	}

	return db
}

func (c *ValkeyDB) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	err := c.valkeyDBConnectionProducer.Initialize(ctx, req.Config, req.VerifyConnection)
	if err != nil {
		return dbplugin.InitializeResponse{}, err
	}
	resp := dbplugin.InitializeResponse{
		Config: req.Config,
	}
	return resp, nil
}

func (c *ValkeyDB) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	// Grab the lock
	c.Lock()
	defer c.Unlock()

	username, err := credsutil.GenerateUsername(
		credsutil.DisplayName(req.UsernameConfig.DisplayName, maxKeyLength),
		credsutil.RoleName(req.UsernameConfig.RoleName, maxKeyLength))
	if err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("failed to generate username: %w", err)
	}
	username = strings.ToUpper(username)

	db, err := c.getConnection(ctx)
	if err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("failed to get connection: %w", err)
	}

	err = newUser(ctx, db, username, req)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	resp := dbplugin.NewUserResponse{
		Username: username,
	}

	return resp, nil
}

func (c *ValkeyDB) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	if req.Password != nil {
		err := c.changeUserPassword(ctx, req.Username, req.Password.NewPassword)
		return dbplugin.UpdateUserResponse{}, err
	}
	return dbplugin.UpdateUserResponse{}, nil
}

func (c *ValkeyDB) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	c.Lock()
	defer c.Unlock()

	db, err := c.getConnection(ctx)
	if err != nil {
		return dbplugin.DeleteUserResponse{}, fmt.Errorf("failed to make connection: %w", err)
	}

	// Close the database connection to ensure no new connections come in
	defer func() {
		if err := c.close(); err != nil {
			logger := hclog.New(&hclog.LoggerOptions{})
			logger.Error("defer close failed", "error", err)
		}
	}()

	var response string

	err = db.Do(ctx, radix.Cmd(&response, "ACL", "DELUSER", req.Username))
	if err != nil {
		return dbplugin.DeleteUserResponse{}, err
	}

	return dbplugin.DeleteUserResponse{}, nil
}

func newUser(ctx context.Context, db radix.Client, username string, req dbplugin.NewUserRequest) error {
	statements := removeEmpty(req.Statements.Commands)
	if len(statements) == 0 {
		statements = append(statements, defaultValkeyUserRule)
	}

	aclargs := []string{"SETUSER", username, "ON", ">" + req.Password}

	var args []string
	err := json.Unmarshal([]byte(statements[0]), &args)
	if err != nil {
		return errwrap.Wrapf("error unmarshalling VALKEY rules in the creation statement JSON: {{err}}", err)
	}

	aclargs = append(aclargs, args...)
	var response string

	err = db.Do(ctx, radix.Cmd(&response, "ACL", aclargs...))
	if err != nil {
		return err
	}

	return nil
}

func (c *ValkeyDB) changeUserPassword(ctx context.Context, username, password string) error {
	c.Lock()
	defer c.Unlock()

	db, err := c.getConnection(ctx)
	if err != nil {
		return err
	}

	// Close the database connection to ensure no new connections come in
	defer func() {
		if err := c.close(); err != nil {
			logger := hclog.New(&hclog.LoggerOptions{})
			logger.Error("defer close failed", "error", err)
		}
	}()

	var response resp3.ArrayHeader
	mn := radix.Maybe{Rcv: &response}
	var valkeyErr resp3.SimpleError
	err = db.Do(ctx, radix.Cmd(&mn, "ACL", "GETUSER", username))
	if errors.As(err, &valkeyErr) {
		return fmt.Errorf("valkey error returned: %s", valkeyErr.Error())
	}

	if err != nil {
		return fmt.Errorf("reset of passwords for user %s failed in changeUserPassword: %w", username, err)
	}

	if mn.Null {
		return fmt.Errorf("changeUserPassword for user %s failed, user not found!", username)
	}

	var sresponse string
	err = db.Do(ctx, radix.Cmd(&sresponse, "ACL", "SETUSER", username, "RESETPASS", ">"+password))
	if err != nil {
		return err
	}

	return nil
}

func removeEmpty(strs []string) []string {
	var newStrs []string
	for _, str := range strs {
		str = strings.TrimSpace(str)
		if str == "" {
			continue
		}
		newStrs = append(newStrs, str)
	}

	return newStrs
}

func computeTimeout(ctx context.Context) (timeout time.Duration) {
	deadline, ok := ctx.Deadline()
	if ok {
		return time.Until(deadline)
	}
	return defaultTimeout
}

func (c *ValkeyDB) getConnection(ctx context.Context) (radix.Client, error) {
	db, err := c.Connection(ctx)
	if err != nil {
		return nil, err
	}
	return db.(radix.Client), nil
}

func (c *ValkeyDB) Type() (string, error) {
	return valkeyTypeName, nil
}
