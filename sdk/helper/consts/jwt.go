package consts

import jose "github.com/go-jose/go-jose/v4"

// JWT signature algorithms allowed for different OpenBao components.
// These slices define the supported signing algorithms for JWT tokens
// in various authentication and authorization contexts.
var (
	// AllowedJWTSignatureAlgorithmsK8s defines the JWT signature algorithms
	// allowed for Kubernetes authentication.
	AllowedJWTSignatureAlgorithmsK8s = []jose.SignatureAlgorithm{
		jose.ES256,
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
	}

	// AllowedJWTSignatureAlgorithmsOIDC defines the JWT signature algorithms
	// allowed for OIDC operations.
	AllowedJWTSignatureAlgorithmsOIDC = []jose.SignatureAlgorithm{
		jose.RS256,
		jose.RS384,
		jose.RS512,
		jose.ES256,
		jose.ES384,
		jose.ES512,
		jose.EdDSA,
	}

	// AllowedJWTSignatureAlgorithmsBao defines the JWT signature algorithms
	// that are supported by OpenBao. Currently uses the same algorithms as OIDC.
	AllowedJWTSignatureAlgorithmsBao = AllowedJWTSignatureAlgorithmsOIDC
)
