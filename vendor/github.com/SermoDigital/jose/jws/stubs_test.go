package jws

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/SermoDigital/jose/crypto"
)

func Error(t *testing.T, want, got interface{}) {
	format := "\nWanted: %s\nGot: %s"

	switch want.(type) {
	case []byte, string, nil, rawBase64, easy:
	default:
		format = fmt.Sprintf(format, "%v", "%v")
	}

	t.Errorf(format, want, got)
}

func ErrorTypes(t *testing.T, want, got interface{}) {
	t.Errorf("\nWanted: %T\nGot: %T", want, got)
}

var (
	rsaPriv   *rsa.PrivateKey
	rsaPub    interface{}
	ec256Priv *ecdsa.PrivateKey
	ec256Pub  *ecdsa.PublicKey
	ec384Priv *ecdsa.PrivateKey
	ec384Pub  *ecdsa.PublicKey
	ec512Priv *ecdsa.PrivateKey
	ec512Pub  *ecdsa.PublicKey
	hm256     interface{}
)

func init() {
	derBytes, err := ioutil.ReadFile(filepath.Join("test", "sample_key.pub"))
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(derBytes)

	rsaPub, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	der, err := ioutil.ReadFile(filepath.Join("test", "sample_key.priv"))
	if err != nil {
		panic(err)
	}
	block2, _ := pem.Decode(der)

	rsaPriv, err = x509.ParsePKCS1PrivateKey(block2.Bytes)
	if err != nil {
		panic(err)
	}

	ecData, err := ioutil.ReadFile(filepath.Join("test", "ec256-private.pem"))
	if err != nil {
		panic(err)
	}
	ec256Priv, err = crypto.ParseECPrivateKeyFromPEM(ecData)
	if err != nil {
		panic(err)
	}
	ecData, err = ioutil.ReadFile(filepath.Join("test", "ec256-public.pem"))
	if err != nil {
		panic(err)
	}
	ec256Pub, err = crypto.ParseECPublicKeyFromPEM(ecData)
	if err != nil {
		panic(err)
	}
	ecData, err = ioutil.ReadFile(filepath.Join("test", "ec384-private.pem"))
	if err != nil {
		panic(err)
	}
	ec384Priv, err = crypto.ParseECPrivateKeyFromPEM(ecData)
	if err != nil {
		panic(err)
	}
	ecData, err = ioutil.ReadFile(filepath.Join("test", "ec384-public.pem"))
	if err != nil {
		panic(err)
	}
	ec384Pub, err = crypto.ParseECPublicKeyFromPEM(ecData)
	if err != nil {
		panic(err)
	}
	ecData, err = ioutil.ReadFile(filepath.Join("test", "ec512-private.pem"))
	if err != nil {
		panic(err)
	}
	ec512Priv, err = crypto.ParseECPrivateKeyFromPEM(ecData)
	if err != nil {
		panic(err)
	}
	ecData, err = ioutil.ReadFile(filepath.Join("test", "ec512-public.pem"))
	if err != nil {
		panic(err)
	}
	ec512Pub, err = crypto.ParseECPublicKeyFromPEM(ecData)
	if err != nil {
		panic(err)
	}

	hm256, err = ioutil.ReadFile(filepath.Join("test", "hmacTestKey"))
	if err != nil {
		panic(err)
	}
}
