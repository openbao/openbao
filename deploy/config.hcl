ui = true

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

storage "file" {
  path = "/bao/data"
}

api_addr = "https://vault.yourdomain.com"
