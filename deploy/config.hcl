ui = true
disable_mlock = true

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

# Storage backend (Integrated Raft is recommended for OpenBao)
storage "raft" {
  path    = "/openbao/file"
  node_id = "openbao_node_1"
}

# In production behind Dokploy / Traefik reverse proxy
api_addr     = "https://openbao.linqoratechnologies.com"
cluster_addr = "http://188.241.62.125:8201"

