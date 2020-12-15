package redis

import (
	"context"
//	"crypto/x509"
//	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mediocregopher/radix/v3"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/database/helper/connutil"
	"github.com/mitchellh/mapstructure"
)

type redisDBConnectionProducer struct {
	PublicKey   string `json:"public_key"`
	PrivateKey  string `json:"private_key"`
	ProjectID   string `json:"project_id"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	TLS         bool   `json:"tls"`
	InsecureTLS bool   `json:"insecure_tls"`
	Base64Pem   string `json:"base64pem"`
	BucketName  string `json:"bucket_name"`

	Initialized bool
	rawConfig   map[string]interface{}
	Type        string
	pool        *radix.Pool
	Addr        string
	sync.Mutex
}

func (c *redisDBConnectionProducer) secretValues() map[string]string {
	return map[string]string{
		c.Password: "[password]",
		c.Username: "[username]",
	}
}

func (c *redisDBConnectionProducer) Init(ctx context.Context, initConfig map[string]interface{}, verifyConnection bool) (saveConfig map[string]interface{}, err error) {

	c.Lock()
	defer c.Unlock()

	c.rawConfig = initConfig

	decoderConfig := &mapstructure.DecoderConfig{
		Result:           c,
		WeaklyTypedInput: true,
		TagName:          "json",
	}

	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return nil, err
	}

	err = decoder.Decode(initConfig)
	if err != nil {
		return nil, err
	}

	switch {
	case len(c.Host) == 0:
		return nil, fmt.Errorf("host cannot be empty")
	case c.Port == 0:
		return nil, fmt.Errorf("port cannot be empty")
	case len(c.Username) == 0:
		return nil, fmt.Errorf("username cannot be empty")
	case len(c.Password) == 0:
		return nil, fmt.Errorf("password cannot be empty")
	}

	c.Addr = fmt.Sprintf("%s:%d", c.Host, c.Port)
	
	if c.TLS {
		if len(c.Base64Pem) == 0 {
			return nil, fmt.Errorf("base64pem cannot be empty")
		}

		if !strings.HasPrefix(c.Host, "couchbases://") {
			return nil, fmt.Errorf("hosts list must start with couchbases:// for TLS connection")
		}
	}

	c.Initialized = true

	if verifyConnection {
		if _, err := c.Connection(ctx); err != nil {
			c.close()
			return nil, errwrap.Wrapf("error verifying connection: {{err}}", err)
		}
		/*var pong string
		if err = c.pool.Do(radix.Cmd(&pong, "PING", "PONG")); err != nil {
			c.close()
			return nil, errwrap.Wrapf("error verifying connection: PONG failed: {{err}}", err)
		}*/
	}

	return initConfig, nil
}

func (c *redisDBConnectionProducer) Initialize(ctx context.Context, config map[string]interface{}, verifyConnection bool) error {
	_, err := c.Init(ctx, config, verifyConnection)
	return err
}
func (c *redisDBConnectionProducer) Connection(ctx context.Context) (interface{}, error) {
	// This is intentionally not grabbing the lock since the calling functions (e.g. CreateUser)
	// are claiming it. (The locking patterns could be refactored to be more consistent/clear.)

	if !c.Initialized {
		return nil, connutil.ErrNotInitialized
	}

	if c.pool != nil {
		return c.pool, nil
	}
	var err error

	customConnFunc := func(network, addr string) (radix.Conn, error) {
		return radix.Dial(network, addr,
			radix.DialTimeout(1 * time.Minute),
			radix.DialAuthUser(c.Username, c.Password),
		)
	}

	c.pool, err = radix.NewPool("tcp", c.Addr, 1, radix.PoolConnFunc(customConnFunc)) // [TODO] poolopts for timeout from ctx??
	if err != nil {
		return nil, errwrap.Wrapf("error in Connection: {{err}}", err)
	}

	return c.pool, nil
}

// close terminates the database connection without locking
func (c *redisDBConnectionProducer) close() error {

	if c.pool != nil {
		if err := c.pool.Close(); err != nil {
			return err
		}
	}

	c.pool = nil
	return nil
}

// Close terminates the database connection with locking
func (c *redisDBConnectionProducer) Close() error {
	c.Lock()
	defer c.Unlock()

	return c.close()
}
