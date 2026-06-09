// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

const (
	ConfigStoragePath = "kmip/config"
	RoleStoragePrefix = "kmip/roles/"
)

type ServerConfig struct {
	Enabled           bool   `json:"enabled"`
	ListenAddr        string `json:"listen_addr"`
	CertPem           string `json:"cert_pem"`
	KeyPem            string `json:"key_pem"`
	TlsCaCertPem      string `json:"tls_ca_cert_pem"`
	RequireClientCert bool   `json:"require_client_cert"`
}

func (c *ServerConfig) Validate() error {
	return nil
}
