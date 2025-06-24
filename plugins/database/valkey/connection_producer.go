// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package valkey

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/go-viper/mapstructure/v2"
	"github.com/mediocregopher/radix/v4"
	"github.com/openbao/openbao/sdk/v2/database/helper/connutil"
)

type valkeyDBConnectionProducer struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	TLS         bool   `json:"tls"`
	InsecureTLS bool   `json:"insecure_tls"`
	CACert      string `json:"ca_cert"`

	Initialized bool
	rawConfig   map[string]interface{}
	Type        string
	client      radix.Client
	Addr        string
	sync.Mutex
}

func (c *valkeyDBConnectionProducer) secretValues() map[string]string {
	return map[string]string{
		c.Password: "[password]",
		c.Username: "[username]",
	}
}

func (c *valkeyDBConnectionProducer) Init(ctx context.Context, initConfig map[string]interface{}, verifyConnection bool) (saveConfig map[string]interface{}, err error) {
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

	c.Addr = net.JoinHostPort(c.Host, strconv.Itoa(c.Port))

	if c.TLS {
		if len(c.CACert) == 0 {
			return nil, fmt.Errorf("ca_cert cannot be empty")
		}
	}

	c.Initialized = true

	if verifyConnection {
		if _, err := c.Connection(ctx); err != nil {
			c.close()
			return nil, fmt.Errorf("error verifying connection: %w", err)
		}
	}

	return initConfig, nil
}

func (c *valkeyDBConnectionProducer) Initialize(ctx context.Context, config map[string]interface{}, verifyConnection bool) error {
	_, err := c.Init(ctx, config, verifyConnection)
	return err
}

func (c *valkeyDBConnectionProducer) Connection(ctx context.Context) (interface{}, error) {
	// This is intentionally not grabbing the lock since the calling functions (e.g. CreateUser)
	// are claiming it. (The locking patterns could be refactored to be more consistent/clear.)

	if !c.Initialized {
		return nil, connutil.ErrNotInitialized
	}

	if c.client != nil {
		return c.client, nil
	}
	var err error
	var poolConfig radix.PoolConfig

	if c.TLS {
		rootCAs := x509.NewCertPool()
		ok := rootCAs.AppendCertsFromPEM([]byte(c.CACert))
		if !ok {
			return nil, fmt.Errorf("failed to parse root certificate")
		}
		poolConfig = radix.PoolConfig{
			Dialer: radix.Dialer{
				AuthUser: c.Username,
				AuthPass: c.Password,
				NetDialer: &tls.Dialer{
					Config: &tls.Config{
						RootCAs:            rootCAs,
						InsecureSkipVerify: c.InsecureTLS,
					},
				},
			},
		}
	} else {
		poolConfig = radix.PoolConfig{
			Dialer: radix.Dialer{
				AuthUser: c.Username,
				AuthPass: c.Password,
			},
		}
	}

	client, err := poolConfig.New(ctx, "tcp", c.Addr)
	if err != nil {
		return nil, err
	}
	c.client = client

	return c.client, nil
}

// close terminates the database connection without locking
func (c *valkeyDBConnectionProducer) close() error {
	if c.client != nil {
		if err := c.client.Close(); err != nil {
			return err
		}
	}

	c.client = nil
	return nil
}

// Close terminates the database connection with locking
func (c *valkeyDBConnectionProducer) Close() error {
	c.Lock()
	defer c.Unlock()

	return c.close()
}
