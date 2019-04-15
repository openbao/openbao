package ldap_test

import (
	"log"

	"gopkg.in/ldap.v2"
)

// ExampleConn_ModifyDN_renameNoMove shows how to rename an entry without moving it
func ExampleConn_ModifyDN_renameNoMove() {
	conn, err := ldap.Dial("tcp", "ldap.example.org:389")
	if err != nil {
		log.Fatalf("Failed to connect: %s\n", err)
	}
	defer conn.Close()

	_, err = conn.SimpleBind(&ldap.SimpleBindRequest{
		Username: "uid=someone,ou=people,dc=example,dc=org",
		Password: "MySecretPass",
	})
	if err != nil {
		log.Fatalf("Failed to bind: %s\n", err)
	}
	// just rename to uid=new,ou=people,dc=example,dc=org:
	req := ldap.NewModifyDNRequest("uid=user,ou=people,dc=example,dc=org", "uid=new", true, "")
	if err = conn.ModifyDN(req); err != nil {
		log.Fatalf("Failed to call ModifyDN(): %s\n", err)
	}
}

// ExampleConn_ModifyDN_renameAndMove shows how to rename an entry and moving it to a new base
func ExampleConn_ModifyDN_renameAndMove() {
	conn, err := ldap.Dial("tcp", "ldap.example.org:389")
	if err != nil {
		log.Fatalf("Failed to connect: %s\n", err)
	}
	defer conn.Close()

	_, err = conn.SimpleBind(&ldap.SimpleBindRequest{
		Username: "uid=someone,ou=people,dc=example,dc=org",
		Password: "MySecretPass",
	})
	if err != nil {
		log.Fatalf("Failed to bind: %s\n", err)
	}
	// rename to uid=new,ou=people,dc=example,dc=org and move to ou=users,dc=example,dc=org ->
	// uid=new,ou=users,dc=example,dc=org
	req := ldap.NewModifyDNRequest("uid=user,ou=people,dc=example,dc=org", "uid=new", true, "ou=users,dc=example,dc=org")

	if err = conn.ModifyDN(req); err != nil {
		log.Fatalf("Failed to call ModifyDN(): %s\n", err)
	}
}

// ExampleConn_ModifyDN_moveOnly shows how to move an entry to a new base without renaming the RDN
func ExampleConn_ModifyDN_moveOnly() {
	conn, err := ldap.Dial("tcp", "ldap.example.org:389")
	if err != nil {
		log.Fatalf("Failed to connect: %s\n", err)
	}
	defer conn.Close()

	_, err = conn.SimpleBind(&ldap.SimpleBindRequest{
		Username: "uid=someone,ou=people,dc=example,dc=org",
		Password: "MySecretPass",
	})
	if err != nil {
		log.Fatalf("Failed to bind: %s\n", err)
	}
	// move to ou=users,dc=example,dc=org -> uid=user,ou=users,dc=example,dc=org
	req := ldap.NewModifyDNRequest("uid=user,ou=people,dc=example,dc=org", "uid=user", true, "ou=users,dc=example,dc=org")
	if err = conn.ModifyDN(req); err != nil {
		log.Fatalf("Failed to call ModifyDN(): %s\n", err)
	}
}
