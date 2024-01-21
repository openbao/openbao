// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"testing"

	"github.com/openbao/openbao/sdk/logical"
)

func TestCheckInAuthorized(t *testing.T) {
	can := checkinAuthorized(&logical.Request{EntityID: "foo"}, &CheckOut{BorrowerEntityID: "foo"})
	if !can {
		t.Fatal("the entity that checked out the secret should be able to check it in")
	}
	can = checkinAuthorized(&logical.Request{ClientToken: "foo"}, &CheckOut{BorrowerClientToken: "foo"})
	if !can {
		t.Fatal("the client token that checked out the secret should be able to check it in")
	}
	can = checkinAuthorized(&logical.Request{EntityID: "fizz"}, &CheckOut{BorrowerEntityID: "buzz"})
	if can {
		t.Fatal("other entities shouldn't be able to perform check-ins")
	}
	can = checkinAuthorized(&logical.Request{ClientToken: "fizz"}, &CheckOut{BorrowerClientToken: "buzz"})
	if can {
		t.Fatal("other tokens shouldn't be able to perform check-ins")
	}
	can = checkinAuthorized(&logical.Request{}, &CheckOut{})
	if can {
		t.Fatal("when insufficient auth info is provided, check-in should not be allowed")
	}
}
