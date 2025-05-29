//go:build !hsm || !(linux || darwin)

package configutil

import (
	"errors"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

func GetPKCS11KMSFunc(kms *KMS, opts ...wrapping.Option) (wrapping.Wrapper, map[string]string, error) {
	return nil, nil, errors.New("this build of OpenBao has PKCS#11 disabled")
}
