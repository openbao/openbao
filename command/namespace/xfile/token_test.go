package xfile

import (
	"testing"

	"github.com/openbao/openbao/api/v2"
)

func TestTokenRoot(t *testing.T) {
	client, ctx, err := getClient()
	if err != nil {
		t.Fatal(err)
	}
	rootToken := client.Token()

	sys := client.Sys()

	mountsRspn, err := sys.ListAuthWithContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for k, rspn := range mountsRspn {
		if !grep([]string{"token/"}, k) {
			t.Errorf("Mount response: %s => %+v", k, rspn)
		}
	}

	path := "token"
	err = sys.DisableAuthWithContext(ctx, path)
	if err == nil {
		t.Fatal("Should have failed")
	} else if rErr, ok := err.(*api.ResponseError); !ok || rErr.StatusCode != 400 || (rErr.Errors)[0] != "token credential backend cannot be disabled" {
		t.Fatalf("%#v", rErr.Errors)
	}

	tokenAuth := client.Auth().Token()
	secret, err := tokenAuth.CreateWithContext(ctx, &api.TokenCreateRequest{
		Policies: []string{"default"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if secret.Auth == nil || secret.Auth.ClientToken == "" {
		t.Errorf("Auth data: %+v", secret.Auth)
	}
	token := secret.Auth.ClientToken
	client.SetToken(token)
	tokenAuth = client.Auth().Token()

	selfSecret, err := tokenAuth.LookupSelfWithContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if selfSecret == nil || selfSecret.Data == nil || selfSecret.Data["policies"] == nil {
		t.Errorf("Self response data nil: %+v", selfSecret)
	}
	policies := selfSecret.Data["policies"].([]interface{})
	if policies[0].(string) != "default" {
		t.Errorf("Policies: %+v", policies)
	}

	client.SetToken(rootToken)
	secret, err = client.Logical().WriteWithContext(ctx, "auth/"+path+"/revoke", map[string]interface{}{
		"token": token,
	})
	if err != nil {
		t.Fatal(err)
	}
	if secret != nil {
		t.Errorf("Secret: %+v", secret)
	}

	_, err = tokenAuth.LookupSelfWithContext(ctx)
	if err != nil {
		if rErr, ok := err.(*api.ResponseError); !ok || rErr.StatusCode != 403 || (rErr.Errors)[0] != "permission denied" {
			t.Fatalf("%#v", rErr.Errors)
		}
	}
}

func TestTokenNamespace(t *testing.T) {
	client, ctx, err := getClient()
	if err != nil {
		t.Fatal(err)
	}
	rootToken := client.Token()

	rootNS := "pname"
	clone, err := cloneClient(ctx, client, rootNS)
	if err != nil {
		t.Fatal(err)
	}

	sys := clone.Sys()
	name := "default"
	policies := []string{name}
	err = sys.PutPolicyWithContext(ctx, name, getDefaultRule())
	if err != nil {
		t.Fatal(err)
	}

	path := "token"
	err = sys.EnableAuthWithOptionsWithContext(ctx, path, &api.EnableAuthOptions{
		Type: "token",
	})
	if err != nil {
		t.Fatal(err)
	}
	mountsRspn, err := sys.ListAuthWithContext(ctx)
	if err != nil {
		t.Errorf("%#v", err)
	}

	for k, rspn := range mountsRspn {
		if !grep([]string{"token/"}, k) {
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
	if len(mountsRspn) != 0 {
		for k, rspn := range mountsRspn {
			t.Errorf("Mount response: %s => %+v", k, rspn)
		}
	}

	err = sys.EnableAuthWithOptionsWithContext(ctx, path, &api.EnableAuthOptions{
		Type: "token",
	})
	if err != nil {
		t.Fatal(err)
	}

	tokenAuth := clone.Auth().Token()
	secret, err := tokenAuth.CreateWithContext(ctx, &api.TokenCreateRequest{
		Policies: policies,
	})
	if err != nil {
		t.Fatal(err)
	}

	if secret.Auth == nil || secret.Auth.ClientToken == "" {
		t.Errorf("Auth data: %+v", secret.Auth)
	}
	token := secret.Auth.ClientToken
	clone.SetToken(token)

	// if we don't put default policy, we would get permission denied here.
	selfSecret, err := tokenAuth.LookupSelfWithContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if selfSecret == nil || selfSecret.Data == nil || selfSecret.Data["policies"] == nil {
		t.Errorf("Self response data nil: %+v", selfSecret)
	}
	data := selfSecret.Data["policies"].([]interface{})
	if data[0].(string) != "default" {
		t.Errorf("Policies: %+v", policies)
	}

	clone.SetToken(rootToken)
	_, err = clone.Logical().WriteWithContext(ctx, "auth/"+path+"/revoke", map[string]interface{}{
		"token": token,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = sys.DisableAuthWithContext(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	err = sys.DeletePolicyWithContext(ctx, name)
	if err != nil {
		if rErr, ok := err.(*api.ResponseError); !ok || rErr.StatusCode != 400 || (rErr.Errors)[0] != "cannot delete default policy" {
			t.Fatalf("%#v", rErr.Errors)
		}
	}

	client.SetNamespace("")
	_, err = client.Logical().DeleteWithContext(ctx, "sys/namespaces/"+rootNS)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTokenMix(t *testing.T) {
	client, ctx, err := getClient()
	if err != nil {
		t.Fatal(err)
	}
	rootToken := client.Token()

	rootNS := "pname"
	clone, err := cloneClient(ctx, client, rootNS)
	if err != nil {
		t.Fatal(err)
	}

	sys := clone.Sys()

	path := "token"
	err = sys.EnableAuthWithOptionsWithContext(ctx, path, &api.EnableAuthOptions{
		Type: "token",
	})
	if err != nil {
		t.Fatal(err)
	}

	// in root namespace
	tokenAuth := client.Auth().Token()
	secret, err := tokenAuth.CreateWithContext(ctx, &api.TokenCreateRequest{
		Policies: []string{"default"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if secret.Auth == nil || secret.Auth.ClientToken == "" {
		t.Errorf("Auth data: %+v", secret.Auth)
	}
	token := secret.Auth.ClientToken
	client.SetToken(token)
	tokenAuth = client.Auth().Token()

	selfSecret, err := tokenAuth.LookupSelfWithContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if selfSecret == nil || selfSecret.Data == nil || selfSecret.Data["policies"] == nil {
		t.Errorf("Self response data nil: %+v", selfSecret)
	}
	data := selfSecret.Data["policies"].([]interface{})
	if data[0].(string) != "default" {
		t.Errorf("Policies: %+v", data)
	}

	// let's add a default policy, then remove it and and disable token auth in namespace
	name := "default"
	err = sys.PutPolicyWithContext(ctx, name, getDefaultRule())
	if err != nil {
		t.Fatal(err)
	}
	err = sys.DisableAuthWithContext(ctx, path)
	if err != nil {
		t.Fatal(err)
	}

	// we show that the root namespace auth is working the same as before
	selfSecret, err = tokenAuth.LookupSelfWithContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if selfSecret == nil || selfSecret.Data == nil || selfSecret.Data["policies"] == nil {
		t.Errorf("Self response data nil: %+v", selfSecret)
	}
	data = selfSecret.Data["policies"].([]interface{})
	if data[0].(string) != "default" {
		t.Errorf("Policies: %+v", data)
	}

	// clean up
	client.SetToken(rootToken)
	secret, err = client.Logical().WriteWithContext(ctx, "auth/"+path+"/revoke", map[string]interface{}{
		"token": token,
	})
	if err != nil {
		t.Fatal(err)
	}
	if secret != nil {
		t.Errorf("Secret: %+v", secret)
	}

	_, err = client.Logical().DeleteWithContext(ctx, "sys/namespaces/"+rootNS)
	if err != nil {
		t.Fatal(err)
	}
}
