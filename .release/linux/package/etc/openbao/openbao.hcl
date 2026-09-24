# Full configuration options can be found at https://openbao.org/docs/configuration.

ui = true

# Read about persistent storage backends at https://openbao.org/docs/configuration/storage.
storage "inmem" {}

# HTTP listener:
#listener "tcp" {
#  address = "127.0.0.1:8200"
#  tls_disable = 1
#}

# HTTPS listener:
listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/opt/openbao/tls/tls.crt"
  tls_key_file  = "/opt/openbao/tls/tls.key"
}
