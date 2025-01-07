package xfile

import (
	"testing"
)

func TestPolicyRootDefault(t *testing.T) {
	client, ctx, err := getClient()
	if err != nil {
		t.Fatal(err)
	}

	logical := client.Logical()

	path := "approle"
	_, secretID, clientToken, err := getApprole(client, ctx, path, "myrole")
	if err != nil {
		t.Fatal(err)
	}

	rootToken := client.Token()
	client.SetToken(clientToken)

	secret, err := logical.ReadWithContext(ctx, "auth/token/lookup-self")
	if err != nil {
		t.Fatal(err)
	}

	if secret == nil || secret.Data == nil {
		t.Errorf("no secret")
	}
	if secret.Data["policies"].([]interface{})[0].(string) != "default" {
		t.Errorf("%#v", secret.Data)
	}

	_, err = logical.ReadWithContext(ctx, "auth/approle/role/myrole")
	if err == nil {
		t.Error("should be 403")
	}

	client.SetToken(rootToken)
	err = dropApprole(client, ctx, secretID, path, "myrole")
	if err != nil {
		t.Fatal(err)
	}
}

func TestPolicyRootCustom(t *testing.T) {
	client, ctx, err := getClient()
	if err != nil {
		t.Fatal(err)
	}

	logical := client.Logical()

	name := "readpolicy"
	policies := []string{name}
	sys := client.Sys()
	err = sys.PutPolicyWithContext(ctx, name, getReadApproleRule())
	if err != nil {
		t.Fatal(err)
	}

	path := "approle"
	_, secretID, clientToken, err := getApprole(client, ctx, path, "myrole", policies...)
	if err != nil {
		t.Fatal(err)
	}

	rootToken := client.Token()
	client.SetToken(clientToken)
	secret, err := logical.ReadWithContext(ctx, "auth/token/lookup-self")
	if err != nil {
		t.Fatal(err)
	}
	if secret == nil || secret.Data == nil {
		t.Errorf("no secret")
	}
	if secret.Data["policies"].([]interface{})[0].(string) != "default" ||
		secret.Data["policies"].([]interface{})[1].(string) != name {
		t.Errorf("%#v", secret.Data)
	}

	secret, err = logical.ReadWithContext(ctx, "auth/approle/role/myrole")
	if err != nil {
		t.Fatal(err)
	}
	if secret == nil || secret.Data == nil {
		t.Errorf("%#v", secret.Data)
	}
	if secret.Data["policies"].([]interface{})[0].(string) != name {
		t.Errorf("%#v", secret.Data)
	}

	client.SetToken(rootToken)
	err = sys.DeletePolicyWithContext(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	err = dropApprole(client, ctx, secretID, path, "myrole")
	if err != nil {
		t.Fatal(err)
	}
}

func TestPolicyNamespaceDefault(t *testing.T) {
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
	logical := clone.Logical()

	name := "default"
	err = sys.PutPolicyWithContext(ctx, name, getDefaultRule())
	if err != nil {
		t.Fatal(err)
	}

	path := "approle"
	_, secretID, clientToken, err := getApprole(clone, ctx, path, "myrole")
	if err != nil {
		t.Fatal(err)
	}

	rootToken := clone.Token()
	clone.SetToken(clientToken)

	secret, err := logical.ReadWithContext(ctx, "auth/token/lookup-self")
	if err != nil {
		t.Fatal(err)
	}
	if secret == nil || secret.Data == nil {
		t.Errorf("no secret")
	}
	if secret.Data["policies"].([]interface{})[0].(string) != name {
		t.Errorf("%#v", secret.Data)
	}

	_, err = logical.ReadWithContext(ctx, "auth/approle/role/myrole")
	if err == nil {
		t.Error("should be 403")
	}

	clone.SetToken(rootToken)
	err = sys.DeletePolicyWithContext(ctx, name)
	if err == nil {
		t.Fatal("default policy cannot be deleted")
	}
	err = dropApprole(clone, ctx, secretID, path, "myrole")
	if err != nil {
		t.Fatal(err)
	}

	client.SetNamespace("")
	_, err = client.Logical().DeleteWithContext(ctx, "sys/namespaces/"+rootNS)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPolicyNamespaceCustom(t *testing.T) {
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
	logical := clone.Logical()

	name := "default"
	err = sys.PutPolicyWithContext(ctx, name, getDefaultRule())
	if err != nil {
		t.Fatal(err)
	}
	nameCustom := "readpolicy"
	err = sys.PutPolicyWithContext(ctx, nameCustom, getReadApproleRule())
	if err != nil {
		t.Fatal(err)
	}
	policies := []string{name, nameCustom}

	path := "approle"
	_, secretID, clientToken, err := getApprole(clone, ctx, path, "myrole", policies...)
	if err != nil {
		t.Fatal(err)
	}

	rootToken := clone.Token()
	clone.SetToken(clientToken)
	secret, err := logical.ReadWithContext(ctx, "auth/token/lookup-self")
	if err != nil {
		t.Fatal(err)
	}
	if secret == nil || secret.Data == nil {
		t.Errorf("no secret")
	}
	ok := (secret.Data["policies"].([]interface{})[0].(string) == name &&
		secret.Data["policies"].([]interface{})[1].(string) == nameCustom) ||
		(secret.Data["policies"].([]interface{})[0].(string) == nameCustom &&
			secret.Data["policies"].([]interface{})[1].(string) == name)
	if !ok {
		t.Errorf("%#v", secret.Data)
	}

	secret, err = logical.ReadWithContext(ctx, "auth/approle/role/myrole")
	if err != nil {
		t.Fatal(err)
	}
	if secret == nil || secret.Data == nil {
		t.Errorf("%#v", secret.Data)
	}

	clone.SetToken(rootToken)
	err = dropApprole(clone, ctx, secretID, path, "myrole")
	if err != nil {
		t.Fatal(err)
	}

	err = sys.DeletePolicyWithContext(ctx, name)
	if err == nil {
		t.Fatal("default policy cannot be deleted")
	}
	err = sys.DeletePolicyWithContext(ctx, nameCustom)
	if err != nil {
		t.Fatal(err)
	}
	arr, err := sys.ListPoliciesWithContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(arr) != 1 || arr[0] != "default" {
		t.Errorf("%#v", arr)
	}

	client.SetNamespace("")
	_, err = client.Logical().DeleteWithContext(ctx, "sys/namespaces/"+rootNS)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPolicyMixDeleteInNamespace(t *testing.T) {
	client, ctx, err := getClient()
	if err != nil {
		t.Fatal(err)
	}

	rootToken := client.Token()
	logical := client.Logical()
	sys := client.Sys()

	rootNS := "pname"
	_, err = logical.WriteWithContext(ctx, "sys/namespaces/"+rootNS, nil)
	if err != nil {
		t.Fatal(err)
	}

	clone, err := client.Clone()
	if err != nil {
		t.Fatal(err)
	}
	clone.SetNamespace(rootNS)
	clone.SetToken(rootToken)
	sysNS := clone.Sys()

	name := "readpolicy"
	policies := []string{name}
	err = sys.PutPolicyWithContext(ctx, name, getReadApproleRule())
	if err != nil {
		t.Fatal(err)
	}

	path := "approle"
	_, secretID, clientToken, err := getApprole(client, ctx, path, "myrole", policies...)
	if err != nil {
		t.Fatal(err)
	}

	client.SetToken(clientToken)
	secret, err := logical.ReadWithContext(ctx, "auth/approle/role/myrole")
	if err != nil {
		t.Fatal(err)
	}
	if secret == nil || secret.Data == nil {
		t.Errorf("%#v", secret.Data)
	}
	if secret.Data["policies"].([]interface{})[0].(string) != name {
		t.Errorf("%#v", secret.Data)
	}

	// add policy name in namespace
	err = sysNS.PutPolicyWithContext(ctx, name, getReadApproleRule())
	if err != nil {
		t.Fatal(err)
	}

	// delete policy name in namespace
	err = sysNS.DeletePolicyWithContext(ctx, name)
	if err != nil {
		t.Fatal(err)
	}

	// to see if the root namespace is not affected
	secret, err = logical.ReadWithContext(ctx, "auth/approle/role/myrole")
	if err != nil {
		t.Fatal(err)
	}
	if secret == nil || secret.Data == nil {
		t.Errorf("%#v", secret.Data)
	}
	if secret.Data["policies"].([]interface{})[0].(string) != name {
		t.Errorf("%#v", secret.Data)
	}

	client.SetToken(rootToken)
	err = sys.DeletePolicyWithContext(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	err = dropApprole(client, ctx, secretID, path, "myrole")
	if err != nil {
		t.Fatal(err)
	}
	_, err = logical.DeleteWithContext(ctx, "sys/namespaces/"+rootNS)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPolicyMixDeleteInRoot(t *testing.T) {
	client, ctx, err := getClient()
	if err != nil {
		t.Fatal(err)
	}

	rootToken := client.Token()
	logical := client.Logical()
	sys := client.Sys()

	rootNS := "pname"
	_, err = logical.WriteWithContext(ctx, "sys/namespaces/"+rootNS, nil)
	if err != nil {
		t.Fatal(err)
	}

	clone, err := client.Clone()
	if err != nil {
		t.Fatal(err)
	}
	clone.SetNamespace(rootNS)
	clone.SetToken(rootToken)
	sysNS := clone.Sys()
	logicalNS := clone.Logical()

	name := "readpolicy"
	err = sys.PutPolicyWithContext(ctx, name, getReadApproleRule())
	if err != nil {
		t.Fatal(err)
	}

	// add name in namespace
	err = sysNS.PutPolicyWithContext(ctx, name, getReadApproleRule())
	if err != nil {
		t.Fatal(err)
	}
	nameDefault := "default"
	err = sysNS.PutPolicyWithContext(ctx, nameDefault, getDefaultRule())
	if err != nil {
		t.Fatal(err)
	}
	policies := []string{name, nameDefault}

	path := "approle"
	_, secretID, clientToken, err := getApprole(clone, ctx, path, "myrole", policies...)
	if err != nil {
		t.Fatal(err)
	}

	clone.SetToken(clientToken)
	secret, err := logicalNS.ReadWithContext(ctx, "auth/approle/role/myrole")
	if err != nil {
		t.Fatal(err)
	}
	if secret == nil || secret.Data == nil {
		t.Errorf("%#v", secret.Data)
	}
	ok := (secret.Data["policies"].([]interface{})[0].(string) == name &&
		secret.Data["policies"].([]interface{})[1].(string) == nameDefault) ||
		(secret.Data["policies"].([]interface{})[0].(string) == nameDefault &&
			secret.Data["policies"].([]interface{})[1].(string) == name)
	if !ok {
		t.Errorf("%#v", secret.Data)
	}

	// delete policy name in root
	err = sys.DeletePolicyWithContext(ctx, name)
	if err != nil {
		t.Fatal(err)
	}

	// to see if the namespace is not affected
	secret, err = logicalNS.ReadWithContext(ctx, "auth/approle/role/myrole")
	if err != nil {
		t.Fatal(err)
	}
	if secret == nil || secret.Data == nil {
		t.Errorf("%#v", secret.Data)
	}
	ok = (secret.Data["policies"].([]interface{})[0].(string) == name &&
		secret.Data["policies"].([]interface{})[1].(string) == nameDefault) ||
		(secret.Data["policies"].([]interface{})[0].(string) == nameDefault &&
			secret.Data["policies"].([]interface{})[1].(string) == name)
	if !ok {
		t.Errorf("%#v", secret.Data)
	}

	clone.SetToken(rootToken)
	err = sys.DeletePolicyWithContext(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	err = dropApprole(clone, ctx, secretID, path, "myrole")
	if err != nil {
		t.Fatal(err)
	}
	_, err = logical.DeleteWithContext(ctx, "sys/namespaces/"+rootNS)
	if err != nil {
		t.Fatal(err)
	}
}
