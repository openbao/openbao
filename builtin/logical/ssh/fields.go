package ssh

import "github.com/openbao/openbao/sdk/v2/framework"

var issuerOKResponseFields = map[string]*framework.FieldSchema{
	"issuer_id": {
		Type:        framework.TypeString,
		Description: `Issuer Id`,
		Required:    false,
	},
	"issuer_name": {
		Type:        framework.TypeString,
		Description: `Issuer Name`,
		Required:    false,
	},
	"public_key": {
		Type:        framework.TypeBool,
		Description: `Issuer public key`,
		Required:    false,
	},
}

func addSubmitIssuerCommonFields(fields map[string]*framework.FieldSchema) map[string]*framework.FieldSchema {
	fields["issuer_name"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Required:    false,
		Description: `Optional issuer name that can be used to identify the issuer.`,
	}

	fields["private_key"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: `Private half of the SSH key that will be used to sign certificates.`,
	}

	fields["public_key"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: `Public half of the SSH key that will be used to sign certificates.`,
	}

	fields["generate_signing_key"] = &framework.FieldSchema{
		Type:        framework.TypeBool,
		Description: `Generate SSH key pair internally rather than use the private_key and public_key fields.`,
		Default:     true,
	}

	fields["key_type"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: `Specifies the desired key type when generating; could be a OpenSSH key type identifier (ssh-rsa, ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, or ssh-ed25519) or an algorithm (rsa, ec, ed25519).`,
		Default:     "ssh-rsa",
	}

	fields["key_bits"] = &framework.FieldSchema{
		Type:        framework.TypeInt,
		Description: `Specifies the desired key bits when generating variable-length keys (such as when key_type="ssh-rsa") or which NIST P-curve to use when key_type="ec" (256, 384, or 521).`,
		Default:     0,
	}

	return fields
}

func addIssuerRefField(fields map[string]*framework.FieldSchema) map[string]*framework.FieldSchema {
	fields[issuerRefParam] = &framework.FieldSchema{
		Type: framework.TypeString,
		Description: `Reference to a existing issuer; either "default"
for the configured default issuer, an identifier or the name assigned
to the issuer.`,
		Default: defaultRef,
	}
	return fields
}

func addIssuerNameField(fields map[string]*framework.FieldSchema) map[string]*framework.FieldSchema {
	fields["issuer_name"] = &framework.FieldSchema{
		Type: framework.TypeString,
		Description: `Provide a name to the generated or existing issuer, the name
must be unique across all issuers and not be the reserved value 'default'`,
	}
	return fields
}
