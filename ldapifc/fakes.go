package ldapifc

import (
	"crypto/tls"
	"fmt"
	"reflect"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/vault/sdk/helper/ldaputil"
)

// FakeLDAPClient can be used to inspect the LDAP requests that have been constructed,
// and to inject responses.
type FakeLDAPClient struct {
	ConnToReturn ldaputil.Connection
}

func (f *FakeLDAPClient) Dial(network, addr string) (ldaputil.Connection, error) {
	return f.ConnToReturn, nil
}

func (f *FakeLDAPClient) DialTLS(network, addr string, config *tls.Config) (ldaputil.Connection, error) {
	return f.ConnToReturn, nil
}

type FakeLDAPConnection struct {
	ModifyRequestToExpect *ldap.ModifyRequest
	SearchRequestToExpect *ldap.SearchRequest
	SearchResultToReturn  *ldap.SearchResult
}

func (f *FakeLDAPConnection) Bind(username, password string) error {
	return nil
}

func (f *FakeLDAPConnection) Close() {}

func (f *FakeLDAPConnection) Modify(modifyRequest *ldap.ModifyRequest) error {
	if !reflect.DeepEqual(f.ModifyRequestToExpect, modifyRequest) {
		return fmt.Errorf("expected modifyRequest of %#v, but received %#v", f.ModifyRequestToExpect, modifyRequest)
	}
	return nil
}

func (f *FakeLDAPConnection) Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if f.SearchRequestToExpect.BaseDN != searchRequest.BaseDN {
		return nil, fmt.Errorf("expected baseDN searchRequest of %v, but received %v", f.SearchRequestToExpect, searchRequest)
	}
	if f.SearchRequestToExpect.Scope != searchRequest.Scope {
		return nil, fmt.Errorf("expected scope searchRequest of %v, but received %v", f.SearchRequestToExpect, searchRequest)
	}
	if f.SearchRequestToExpect.Filter != searchRequest.Filter {
		return nil, fmt.Errorf("expected filter searchRequest of %v, but received %v", f.SearchRequestToExpect, searchRequest)
	}
	return f.SearchResultToReturn, nil
}

func (f *FakeLDAPConnection) StartTLS(config *tls.Config) error {
	return nil
}

func (f *FakeLDAPConnection) SetTimeout(timeout time.Duration) {}

func (f *FakeLDAPConnection) UnauthenticatedBind(username string) error {
	return nil
}
