package xfile

import (
	"testing"

	"github.com/openbao/openbao/api/v2"
)

func TestKVRoot(t *testing.T) {
	client, ctx, err := getClient()
	if err != nil {
		t.Fatal(err)
	}

	sys := client.Sys()

	// mount kv
	path := "secret"
	err = sys.MountWithContext(ctx, path, &api.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
			"upgrade": "false",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	mountsRspn, err := sys.ListMountsWithContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for k, rspn := range mountsRspn {
		if !grep([]string{"secret/", "cubbyhole/", "identity/", "sys/"}, k) {
			t.Errorf("Mount response: %s => %+v", k, rspn)
		}
	}

	kv2 := client.KVv2(path)
	name := "mysecret"

	var kvSecret *api.KVSecret
	kvSecret, err = kv2.Put(ctx, name, map[string]interface{}{
		"username": "myadmin",
		"password": "123456",
	})
	if err != nil {
		t.Fatal(err)
	}
	if kvSecret.Data != nil {
		t.Errorf("KV secret: %#v", kvSecret.Data)
	}

	kvSecret, err = kv2.Get(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if kvSecret.Data == nil ||
		kvSecret.Data["username"].(string) != "myadmin" ||
		kvSecret.Data["password"].(string) != "123456" {
		t.Errorf("KV secret: %#v", kvSecret.Data)
	}

	err = kv2.Delete(ctx, name)
	if err != nil {
		t.Fatal(err)
	}

	_, err = kv2.Put(ctx, name, map[string]interface{}{
		"username": "myadmin7",
		"password": "1234567",
	})
	if err != nil {
		t.Fatal(err)
	}

	kvSecret, err = kv2.Get(ctx, name)
	if err != nil {
		t.Errorf("KV secret: %+v", err)
	}
	if kvSecret.Data == nil ||
		kvSecret.Data["username"].(string) != "myadmin7" ||
		kvSecret.Data["password"].(string) != "1234567" {
		t.Errorf("KV secret: %#v", kvSecret.Data)
	}

	err = kv2.Delete(ctx, name)
	if err != nil {
		t.Fatal(err)
	}

	err = sys.UnmountWithContext(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	mountsRspn, err = sys.ListMountsWithContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for k, rspn := range mountsRspn {
		if !grep([]string{"cubbyhole/", "identity/", "sys/"}, k) {
			t.Errorf("Mount response: %s => %+v", k, rspn)
		}
	}

	err = sys.MountWithContext(ctx, path, &api.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
			"upgrade": "false",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = sys.UnmountWithContext(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
}

func TestKVNamespace(t *testing.T) {
	client, ctx, err := getClient()
	if err != nil {
		t.Fatal(err)
	}

	pname := "pname"
	clone, err := cloneClient(ctx, client, pname)
	if err != nil {
		t.Fatal(err)
	}

	sys := clone.Sys()

	path := "secret"
	err = sys.MountWithContext(ctx, path, &api.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
			"upgrade": "false",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	mountsRspn, err := sys.ListMountsWithContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for k, rspn := range mountsRspn {
		if !grep([]string{"secret/", "cubbyhole/", "identity/", "sys/"}, k) {
			t.Errorf("Mount response: %s => %+v", k, rspn)
		}
	}

	kv2 := client.KVv2(path)
	name := "yoursecret"

	var kvSecret *api.KVSecret
	kvSecret, err = kv2.Put(ctx, name, map[string]interface{}{
		"username": "youradmin",
		"password": "000000",
	})
	if err != nil {
		t.Fatal(err)
	}
	if kvSecret.Data != nil {
		t.Errorf("KV secret: %#v", kvSecret.Data)
	}

	kvSecret, err = kv2.Get(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if kvSecret.Data == nil ||
		kvSecret.Data["username"].(string) != "youradmin" ||
		kvSecret.Data["password"].(string) != "000000" {
		t.Errorf("KV secret: %#v", kvSecret.Data)
	}

	err = kv2.Delete(ctx, name)
	if err != nil {
		t.Fatal(err)
	}

	_, err = kv2.Put(ctx, name, map[string]interface{}{
		"username": "youradmin7",
		"password": "0000007",
	})
	if err != nil {
		t.Fatal(err)
	}

	kvSecret, err = kv2.Get(ctx, name)
	if err != nil {
		t.Errorf("KV secret: %+v", err)
	}
	if kvSecret.Data == nil ||
		kvSecret.Data["username"].(string) != "youradmin7" ||
		kvSecret.Data["password"].(string) != "0000007" {
		t.Errorf("KV secret: %#v", kvSecret.Data)
	}

	err = kv2.Delete(ctx, name)
	if err != nil {
		t.Fatal(err)
	}

	err = sys.UnmountWithContext(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	mountsRspn, err = sys.ListMountsWithContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for k, rspn := range mountsRspn {
		if !grep([]string{"cubbyhole/", "identity/", "sys/"}, k) {
			t.Errorf("Mount response: %s => %+v", k, rspn)
		}
	}

	err = sys.MountWithContext(ctx, path, &api.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
			"upgrade": "false",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = sys.UnmountWithContext(ctx, path)
	if err != nil {
		t.Fatal(err)
	}

	client.SetNamespace("")
	_, err = client.Logical().DeleteWithContext(ctx, "sys/namespaces/"+pname)
	if err != nil {
		t.Fatal(err)
	}
}

func TestKVNegative(t *testing.T) {
	client, ctx, err := getClient()
	if err != nil {
		t.Fatal(err)
	}

	// in root namespace
	sys := client.Sys()
	logical := client.Logical()

	path := "secret"
	err = sys.MountWithContext(ctx, path, &api.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
			"upgrade": "false",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	kv2 := client.KVv2(path)
	name := "mysecret"

	var kvSecret *api.KVSecret
	_, err = kv2.Put(ctx, name, map[string]interface{}{
		"username": "myadmin",
		"password": "123456",
	})
	if err != nil {
		t.Fatal(err)
	}

	pname := "pname"
	clone, err := cloneClient(ctx, client, pname)
	if err != nil {
		t.Fatal(err)
	}

	sysNS := clone.Sys()

	// in child namespace
	err = sysNS.MountWithContext(ctx, path, &api.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
			"upgrade": "false",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	kvNS := clone.KVv2(path)

	nameNS := "yoursecret"
	_, err = kvNS.Put(ctx, nameNS, map[string]interface{}{
		"username": "youradmin",
		"password": "000000",
	})
	if err != nil {
		t.Fatal(err)
	}

	kvSecret, err = kvNS.Get(ctx, name)
	// kvNS tries to get a secret in root namespace
	if err == nil || (err.Error())[:16] != "secret not found" {
		t.Errorf("KV secret: %+v", kvSecret)
		t.Fatal(err)
	}

	// in root namespace
	client.SetNamespace("") // just to setup again, maybe not necessary
	kvSecret, err = kv2.Get(ctx, nameNS)
	// kv2 tries to get a secret in child namespace
	if err == nil || (err.Error())[:16] != "secret not found" {
		t.Errorf("KV secret: %+v", kvSecret)
		t.Fatal(err)
	}

	// cleanup
	if err = kvNS.Delete(ctx, nameNS); err == nil {
		if err = sysNS.UnmountWithContext(ctx, path); err == nil {
			if err = sysNS.MountWithContext(ctx, path, &api.MountInput{
				Type: "kv",
				Options: map[string]string{
					"version": "2",
					"upgrade": "false",
				},
			}); err == nil {
				err = sysNS.UnmountWithContext(ctx, path)
			}
		}
	}
	if err != nil {
		t.Fatal(err)
	}

	if err = kv2.Delete(ctx, name); err == nil {
		if err = sys.UnmountWithContext(ctx, path); err == nil {
			if err = sys.MountWithContext(ctx, path, &api.MountInput{
				Type: "kv",
				Options: map[string]string{
					"version": "2",
					"upgrade": "false",
				},
			}); err == nil {
				err = sys.UnmountWithContext(ctx, path)
			}
		}
	}
	if err != nil {
		t.Fatal(err)
	}

	_, err = logical.DeleteWithContext(ctx, "sys/namespaces/"+pname)
	if err != nil {
		t.Fatal(err)
	}
}
