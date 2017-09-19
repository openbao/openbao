package jws

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/SermoDigital/jose/crypto"
)

var claims = Claims{
	"name": "Eric",
	"scopes": []string{
		"user.account.info",
		"user.account.update",
		"user.account.delete",
	},
	"admin": true,
	"data": struct {
		Foo, Bar int
	}{
		Foo: 12,
		Bar: 50,
	},
}

func TestBasicJWT(t *testing.T) {
	j := NewJWT(claims, crypto.SigningMethodRS512)
	b, err := j.Serialize(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	w, err := ParseJWT(b)
	if err != nil {
		t.Error(err)
	}

	if w.Claims().Get("name") != "Eric" &&
		w.Claims().Get("admin") != true &&
		w.Claims().Get("scopes").([]string)[0] != "user.account.info" {
		Error(t, claims, w.Claims())
	}

	if err := w.Validate(rsaPub, crypto.SigningMethodRS512); err != nil {
		t.Error(err)
	}
}

func TestJWTValidator(t *testing.T) {
	j := NewJWT(claims, crypto.SigningMethodRS512)
	j.Claims().SetIssuer("example.com")

	b, err := j.Serialize(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	w, err := ParseJWT(b)
	if err != nil {
		t.Error(err)
	}

	d := time.Hour
	fn := func(c Claims) error {

		scopes, ok := c.Get("scopes").([]interface{})

		if !ok {
			return errors.New("Unexpected scopes type. Expected string")
		}

		if c.Get("name") != "Eric" &&
			c.Get("admin") != true &&
			scopes[0] != "user.account.info" {
			return errors.New("invalid")
		}
		return nil
	}
	v := NewValidator(Claims{"iss": "example.com"}, d, d, fn)
	if err := w.Validate(rsaPub, crypto.SigningMethodRS512, v); err != nil {
		t.Error(err)
	}
}

func TestFromHeader(t *testing.T) {
	header := http.Header{}
	req := &http.Request{
		Header: header,
	}

	_, ok := fromHeader(req)
	if ok {
		t.Errorf("fromHeader should return !ok when request doesn't have an authorization header")
	}

	header.Set("Authorization", "invalid")
	_, ok = fromHeader(req)
	if ok {
		t.Errorf("fromHeader should return !ok when Authorization header value is invalid")
	}

	header.Set("Authorization", "bearer")
	_, ok = fromHeader(req)
	if ok {
		t.Errorf("fromHeader should return !ok when Authorization header value doesn't contain any value for a token")
	}

	header.Set("Authorization", "bearer ")
	_, ok = fromHeader(req)
	if ok {
		t.Errorf("fromHeader should return !ok when Authorization header value doesn't contain any value for a token")
	}

	header.Set("Authorization", "BEARER ")
	_, ok = fromHeader(req)
	if ok {
		t.Errorf("fromHeader should return !ok when Authorization header value doesn't contain any value for a token")
	}

	header.Set("Authorization", "BEARER t")
	token, ok := fromHeader(req)
	if !ok {
		t.Errorf("fromHeader should return ok when Authorization header contains a value for a token")
	}

	if string(token) != "t" {
		t.Errorf("fromHeader should return the value set as token in the Auhorization header")
	}
}
