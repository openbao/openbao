initialize "identity" {
  request "mount-userpass" {
    operation = "update"
    path = "sys/auth/userpass"
    data = {
      "type" = "userpass"
      "path" = "userpass"
    }
  }

  request "userpass-add-admin" {
    operation = "update"
    path = "auth/userpass/users/admin"
    data = {
      "password" = "password"
      "token_policies" = ["superuser"]
    }
  }
}

initialize "policy" {
  request "add-superuser-policy" {
    operation = "update"    
    path = "sys/policies/acl/superuser"
    data = {
      policy = <<-EOF
        path "*" {
          capabilities = ["create", "update", "read", "delete", "list", "scan", "sudo"]
        }
      EOF
    }
  }
}
