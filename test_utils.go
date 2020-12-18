package redis

import (
//	"encoding/base64"
//	"encoding/json"
	"fmt"
//	"io/ioutil"
//	"net/http"
//	"net/url"
//	"strings"
	"time"

	"github.com/mediocregopher/radix/v3"
	"github.com/hashicorp/errwrap"
//	"github.com/cenkalti/backoff"
//	"github.com/hashicorp/go-version"
)

func createUser(hostname string, port int, adminuser, adminpassword, username, password, aclRule string) (err error) {
	
	customConnFunc := func(network, addr string) (radix.Conn, error) {
		return radix.Dial(network, addr,
			radix.DialTimeout(1 * time.Minute),
			radix.DialAuthUser(adminuser, adminpassword),
		)
	}

	addr := fmt.Sprintf("%s:%d", hostname, port)
	
	pool, err := radix.NewPool("tcp", addr, 1, radix.PoolConnFunc(customConnFunc)) // [TODO] poolopts for timeout from ctx??
	if err != nil {
		return errwrap.Wrapf("error in Connection: {{err}}", err)
	}

	var response string
	
	err = pool.Do(radix.Cmd(&response, "ACL", "SETUSER", username, "on", ">" + password, aclRule))

	fmt.Printf("Response in createUser: %s\n", response)

	if err != nil {
		return err
	}

	if pool != nil {
		if err = pool.Close(); err != nil {
			return err
		}
	}


	return nil
}


