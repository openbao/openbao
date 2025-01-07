package xfile

import (
	"testing"

	"github.com/openbao/openbao/api/auth/approle/v2"
	"github.com/openbao/openbao/api/v2"
)

func TestApproleRoot(t *testing.T) {
	client, ctx, err := getClient()
	if err != nil {
		t.Fatal(err)
	}

	sys := client.Sys()

	path := "approle"
	err = sys.EnableAuthWithOptionsWithContext(ctx, path, &api.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		t.Fatal(err)
	}
	mountsRspn, err := sys.ListAuthWithContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for k, rspn := range mountsRspn {
		if !grep([]string{"token/", "approle/"}, k) {
			t.Errorf("Mount response: %s => %+v", k, rspn)
		}
	}

	err = sys.DisableAuthWithContext(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	mountsRspn, err = sys.ListAuthWithContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for k, rspn := range mountsRspn {
		if !grep([]string{"token/"}, k) {
			t.Errorf("Mount response: %s => %+v", k, rspn)
		}
	}

	_, secretID, clientToken, err := getApprole(client, ctx, path, "myrole")
	if err != nil {
		t.Fatal(err)
	}
	if clientToken == "" {
		t.Errorf("no client token")
	}

	err = dropApprole(client, ctx, secretID, path, "myrole")
	if err != nil {
		t.Fatal(err)
	}
}

func TestApproleNamespace(t *testing.T) {
	client, ctx, err := getClient()
	if err != nil {
		t.Fatal(err)
	}

	rootNS := "pname"
	clone, err := cloneClient(ctx, client, rootNS)
	if err != nil {
		t.Fatal(err)
	}

	sys := clone.Sys()

	path := "approle"
	err = sys.EnableAuthWithOptionsWithContext(ctx, path, &api.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		t.Fatal(err)
	}
	mountsRspn, err := sys.ListAuthWithContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for k, rspn := range mountsRspn {
		if !grep([]string{"token/", "approle/"}, k) {
			t.Errorf("Mount response: %s => %+v", k, rspn)
		}
	}

	err = sys.DisableAuthWithContext(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	mountsRspn, err = sys.ListAuthWithContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for k, rspn := range mountsRspn {
		if !grep([]string{"token/"}, k) {
			t.Errorf("Mount response: %s => %+v", k, rspn)
		}
	}

	_, secretID, clientToken, err := getApprole(clone, ctx, path, "myrole")
	if err != nil {
		t.Fatal(err)
	}
	if clientToken == "" {
		t.Errorf("no client token")
	}

	err = dropApprole(clone, ctx, secretID, path, "myrole")
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().DeleteWithContext(ctx, "sys/namespaces/"+rootNS)
	if err != nil {
		t.Fatal(err)
	}
}

func TestApproleMix(t *testing.T) {
	client, ctx, err := getClient()
	if err != nil {
		t.Fatal(err)
	}

	rootNS := "pname"
	clone, err := cloneClient(ctx, client, rootNS)
	if err != nil {
		t.Fatal(err)
	}

	path := "approle"

	var secret *api.Secret
	var roleID, secretID, clientToken, roleNS, secretNS, clientTokenNS string

	roleID, secretID, clientToken, err = getApprole(client, ctx, path, "myrole")
	if err != nil {
		t.Fatal(err)
	}
	if clientToken == "" {
		t.Errorf("no client token")
	}

	roleNS, secretNS, clientTokenNS, err = getApprole(clone, ctx, path, "yourrole")
	if err != nil {
		t.Fatal(err)
	}
	if clientTokenNS == "" {
		t.Errorf("no client token")
	}

	auth, err := approle.NewAppRoleAuth(roleID, &approle.SecretID{FromString: secretID})
	if err != nil {
		t.Fatal(err)
	}
	secret, err = auth.Login(ctx, clone)
	if err == nil {
		t.Errorf("error should exist, but we got nil. secret id: %#v", secret)
	}

	authNS, err := approle.NewAppRoleAuth(roleNS, &approle.SecretID{FromString: secretNS})
	if err != nil {
		t.Fatal(err)
	}
	secret, err = authNS.Login(ctx, client)
	if err == nil {
		t.Errorf("error should exist, but we got nil. secret id: %#v", secret)
	}

	err = dropApprole(clone, ctx, secretNS, path, "yourrole")
	if err != nil {
		t.Fatal(err)
	}

	err = dropApprole(client, ctx, secretID, path, "myrole")
	if err != nil {
		t.Fatal(err)
	}

	client.SetNamespace("")
	_, err = client.Logical().DeleteWithContext(ctx, "sys/namespaces/"+rootNS)
	if err != nil {
		t.Fatal(err)
	}
}
