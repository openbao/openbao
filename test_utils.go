package redis

import (
	"context"
	"fmt"

	"github.com/mediocregopher/radix/v4"
)

func createUser(hostname string, port int, adminuser, adminpassword, username, password, aclRule string) (err error) {
	poolConfig := radix.PoolConfig{
		Dialer: radix.Dialer{
			AuthUser: adminuser,
			AuthPass: adminpassword,
		},
	}

	addr := fmt.Sprintf("%s:%d", hostname, port)
	client, err := poolConfig.New(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}

	var response string
	err = client.Do(context.Background(), radix.Cmd(&response, "ACL", "SETUSER", username, "on", ">"+password, aclRule))

	fmt.Printf("Response in createUser: %s\n", response)

	if err != nil {
		return err
	}

	if client != nil {
		if err = client.Close(); err != nil {
			return err
		}
	}

	return nil
}
