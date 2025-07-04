package consts

import jose "github.com/go-jose/go-jose/v4"

// JWT signature algorithms allowed for different OpenBao components.
// These slices define the supported signing algorithms for JWT tokens
// in various authentication and authorization contexts.
var (
	// AllowedJWTSignatureAlgorithmsBao defines the JWT signature algorithms
	// allowed for OpenBao.
	AllowedJWTSignatureAlgorithmsBao = []jose.SignatureAlgorithm{
		jose.ES256,
		jose.ES384,
		jose.ES512,
		jose.EdDSA,
		jose.RS256,
		jose.RS384,
		jose.RS512,
		jose.PS256,
		jose.PS384,
		jose.PS512,
	}

	// AllowedJWTSignatureAlgorithmsPKI defines the JWT signature algorithms
	// allowed for PKI operations.
	AllowedJWTSignatureAlgorithmsPKI = []jose.SignatureAlgorithm{
		jose.RS256,
		jose.RS384,
		jose.RS512,
		jose.PS256,
		jose.PS384,
		jose.PS512,
		jose.ES256,
		jose.ES384,
		jose.ES512,
		jose.EdDSA,
		jose.HS256,
		jose.HS384,
		jose.HS512,
	}

	// AllowedJWTSignatureAlgorithmsK8s defines the JWT signature algorithms
	// that are supported by Kubernetes.
	AllowedJWTSignatureAlgorithmsK8s = AllowedJWTSignatureAlgorithmsBao

	// AllowedJWTSignatureAlgorithmsOIDC defines the JWT signature algorithms
	// that are supported by OIDC.
	AllowedJWTSignatureAlgorithmsOIDC = AllowedJWTSignatureAlgorithmsBao
)
