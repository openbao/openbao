// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ldapifc

import (
	"crypto/tls"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/openbao/openbao/sdk/v2/helper/ldaputil"
)

// FakeLDAPClient can be used to inspect the LDAP requests that have been constructed,
// and to inject responses.
type FakeLDAPClient struct {
	ConnToReturn ldaputil.Connection
}

func (f *FakeLDAPClient) DialURL(addr string, opts ...ldap.DialOpt) (ldaputil.Connection, error) {
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

func (f *FakeLDAPConnection) Close() error {
	return nil
}

func (f *FakeLDAPConnection) Modify(modifyRequest *ldap.ModifyRequest) error {
	// Sort the change slices before comparison because they are added in a random order
	sort.Slice(f.ModifyRequestToExpect.Changes, func(i, j int) bool {
		return f.ModifyRequestToExpect.Changes[i].Modification.Type < f.ModifyRequestToExpect.Changes[j].Modification.Type
	})
	sort.Slice(modifyRequest.Changes, func(i, j int) bool {
		return modifyRequest.Changes[i].Modification.Type < modifyRequest.Changes[j].Modification.Type
	})

	if !reflect.DeepEqual(f.ModifyRequestToExpect, modifyRequest) {
		return fmt.Errorf("Actual modify request: %#v\nExpected: %#v", modifyRequest, f.ModifyRequestToExpect)
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

func (f *FakeLDAPConnection) Add(request *ldap.AddRequest) error {
	return nil
}

func (f *FakeLDAPConnection) Del(request *ldap.DelRequest) error {
	return nil
}
