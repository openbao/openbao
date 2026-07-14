// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/errutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const latestCrlConfigVersion = 1

// CRLConfig holds basic CRL configuration information
type crlConfig struct {
	Version                    int    `json:"version"`
	Expiry                     string `json:"expiry"`
	Disable                    bool   `json:"disable"`
	OcspDisable                bool   `json:"ocsp_disable"`
	AutoRebuild                bool   `json:"auto_rebuild"`
	AutoRebuildGracePeriod     string `json:"auto_rebuild_grace_period"`
	OcspExpiry                 string `json:"ocsp_expiry"`
	EnableDelta                bool   `json:"enable_delta"`
	DeltaRebuildInterval       string `json:"delta_rebuild_interval"`
	AllowExpiredCertRevocation bool   `json:"allow_expired_cert_revocation"`
}

// Implicit default values for the config if it does not exist.
var defaultCrlConfig = crlConfig{
	Version:                    latestCrlConfigVersion,
	Expiry:                     "72h",
	Disable:                    false,
	OcspDisable:                false,
	OcspExpiry:                 "12h",
	AutoRebuild:                false,
	AutoRebuildGracePeriod:     "12h",
	EnableDelta:                false,
	DeltaRebuildInterval:       "15m",
	AllowExpiredCertRevocation: false,
}

func pathConfigCRL(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/crl",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
		},

		Fields: map[string]*framework.FieldSchema{
			"expiry": {
				Type: framework.TypeString,
				Description: `The amount of time the generated CRL should be
valid; defaults to 72 hours`,
				Default: "72h",
			},
			"disable": {
				Type:        framework.TypeBool,
				Description: `If set to true, disables generating the CRL entirely.`,
			},
			"ocsp_disable": {
				Type:        framework.TypeBool,
				Description: `If set to true, ocsp unauthorized responses will be returned.`,
			},
			"ocsp_expiry": {
				Type: framework.TypeString,
				Description: `The amount of time an OCSP response will be valid (controls 
the NextUpdate field); defaults to 12 hours`,
				Default: "1h",
			},
			"auto_rebuild": {
				Type:        framework.TypeBool,
				Description: `If set to true, enables automatic rebuilding of the CRL`,
			},
			"auto_rebuild_grace_period": {
				Type:        framework.TypeString,
				Description: `The time before the CRL expires to automatically rebuild it, when enabled. Must be shorter than the CRL expiry. Defaults to 12h.`,
				Default:     "12h",
			},
			"enable_delta": {
				Type:        framework.TypeBool,
				Description: `Whether to enable delta CRLs between authoritative CRL rebuilds`,
			},
			"delta_rebuild_interval": {
				Type:        framework.TypeString,
				Description: `The time between delta CRL rebuilds if a new revocation has occurred. Must be shorter than the CRL expiry. Defaults to 15m.`,
				Default:     "15m",
			},
			"allow_expired_cert_revocation": {
				Type:        framework.TypeBool,
				Description: `If set to true, allows the revocation of expired certificates.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "crl-configuration",
				},
				Callback: b.pathCRLRead,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"expiry": {
								Type: framework.TypeString,
								Description: `The amount of time the generated CRL should be
valid; defaults to 72 hours`,
								Required: true,
							},
							"disable": {
								Type:        framework.TypeBool,
								Description: `If set to true, disables generating the CRL entirely.`,
								Required:    true,
							},
							"ocsp_disable": {
								Type:        framework.TypeBool,
								Description: `If set to true, ocsp unauthorized responses will be returned.`,
								Required:    true,
							},
							"ocsp_expiry": {
								Type: framework.TypeString,
								Description: `The amount of time an OCSP response will be valid (controls 
the NextUpdate field); defaults to 12 hours`,
								Required: true,
							},
							"auto_rebuild": {
								Type:        framework.TypeBool,
								Description: `If set to true, enables automatic rebuilding of the CRL`,
								Required:    true,
							},
							"auto_rebuild_grace_period": {
								Type:        framework.TypeString,
								Description: `The time before the CRL expires to automatically rebuild it, when enabled. Must be shorter than the CRL expiry. Defaults to 12h.`,
								Required:    true,
							},
							"enable_delta": {
								Type:        framework.TypeBool,
								Description: `Whether to enable delta CRLs between authoritative CRL rebuilds`,
								Required:    true,
							},
							"delta_rebuild_interval": {
								Type:        framework.TypeString,
								Description: `The time between delta CRL rebuilds if a new revocation has occurred. Must be shorter than the CRL expiry. Defaults to 15m.`,
								Required:    true,
							},
							"allow_expired_cert_revocation": {
								Type:        framework.TypeBool,
								Description: `If set to true, allows the revocation of expired certificates.`,
								Required:    true,
							},
						},
					}},
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathCRLWrite,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "configure",
					OperationSuffix: "crl",
				},
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"expiry": {
								Type: framework.TypeString,
								Description: `The amount of time the generated CRL should be
valid; defaults to 72 hours`,
								Default: "72h",
							},
							"disable": {
								Type:        framework.TypeBool,
								Description: `If set to true, disables generating the CRL entirely.`,
							},
							"ocsp_disable": {
								Type:        framework.TypeBool,
								Description: `If set to true, ocsp unauthorized responses will be returned.`,
							},
							"ocsp_expiry": {
								Type: framework.TypeString,
								Description: `The amount of time an OCSP response will be valid (controls 
the NextUpdate field); defaults to 12 hours`,
								Default: "1h",
							},
							"auto_rebuild": {
								Type:        framework.TypeBool,
								Description: `If set to true, enables automatic rebuilding of the CRL`,
							},
							"auto_rebuild_grace_period": {
								Type:        framework.TypeString,
								Description: `The time before the CRL expires to automatically rebuild it, when enabled. Must be shorter than the CRL expiry. Defaults to 12h.`,
								Default:     "12h",
							},
							"enable_delta": {
								Type:        framework.TypeBool,
								Description: `Whether to enable delta CRLs between authoritative CRL rebuilds`,
							},
							"delta_rebuild_interval": {
								Type:        framework.TypeString,
								Description: `The time between delta CRL rebuilds if a new revocation has occurred. Must be shorter than the CRL expiry. Defaults to 15m.`,
								Default:     "15m",
							},
							"allow_expired_cert_revocation": {
								Type:        framework.TypeBool,
								Description: `If set to true, allows the revocation of expired certificates.`,
							},
						},
					}},
				},
				// Read more about why these flags are set in backend.go.
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},

		HelpSynopsis:    pathConfigCRLHelpSyn,
		HelpDescription: pathConfigCRLHelpDesc,
	}
}

func (b *backend) pathCRLRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)
	config, err := sc.getRevocationConfig()
	if err != nil {
		return nil, err
	}

	return genResponseFromCrlConfig(config), nil
}

func (b *backend) pathCRLWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)
	config, err := sc.getRevocationConfig()
	if err != nil {
		return nil, err
	}

	if expiryRaw, ok := d.GetOk("expiry"); ok {
		expiry := expiryRaw.(string)
		_, err := parseutil.ParseDurationSecond(expiry)
		if err != nil {
			return logical.ErrorResponse("given expiry could not be decoded: %s", err), nil
		}
		config.Expiry = expiry
	}

	oldDisable := config.Disable
	if disableRaw, ok := d.GetOk("disable"); ok {
		config.Disable = disableRaw.(bool)
	}

	if ocspDisableRaw, ok := d.GetOk("ocsp_disable"); ok {
		config.OcspDisable = ocspDisableRaw.(bool)
	}

	if expiryRaw, ok := d.GetOk("ocsp_expiry"); ok {
		expiry := expiryRaw.(string)
		duration, err := parseutil.ParseDurationSecond(expiry)
		if err != nil {
			return logical.ErrorResponse("given ocsp_expiry could not be decoded: %s", err), nil
		}
		if duration < 0 {
			return logical.ErrorResponse("ocsp_expiry must be greater than or equal to 0 got: %s", duration), nil
		}
		config.OcspExpiry = expiry
	}

	oldAutoRebuild := config.AutoRebuild
	if autoRebuildRaw, ok := d.GetOk("auto_rebuild"); ok {
		config.AutoRebuild = autoRebuildRaw.(bool)
	}

	if autoRebuildGracePeriodRaw, ok := d.GetOk("auto_rebuild_grace_period"); ok {
		autoRebuildGracePeriod := autoRebuildGracePeriodRaw.(string)
		if _, err := parseutil.ParseDurationSecond(autoRebuildGracePeriod); err != nil {
			return logical.ErrorResponse("given auto_rebuild_grace_period could not be decoded: %s", err), nil
		}
		config.AutoRebuildGracePeriod = autoRebuildGracePeriod
	}

	oldEnableDelta := config.EnableDelta
	if enableDeltaRaw, ok := d.GetOk("enable_delta"); ok {
		config.EnableDelta = enableDeltaRaw.(bool)
	}

	if deltaRebuildIntervalRaw, ok := d.GetOk("delta_rebuild_interval"); ok {
		deltaRebuildInterval := deltaRebuildIntervalRaw.(string)
		if _, err := parseutil.ParseDurationSecond(deltaRebuildInterval); err != nil {
			return logical.ErrorResponse("given delta_rebuild_interval could not be decoded: %s", err), nil
		}
		config.DeltaRebuildInterval = deltaRebuildInterval
	}

	if allowExpiredCertRevocationRaw, ok := d.GetOk("allow_expired_cert_revocation"); ok {
		config.AllowExpiredCertRevocation = allowExpiredCertRevocationRaw.(bool)
	}

	expiry, _ := parseutil.ParseDurationSecond(config.Expiry)
	if config.AutoRebuild {
		gracePeriod, _ := parseutil.ParseDurationSecond(config.AutoRebuildGracePeriod)
		if gracePeriod >= expiry {
			return logical.ErrorResponse("CRL auto-rebuilding grace period (%v) must be strictly shorter than CRL expiry (%v) value when auto-rebuilding of CRLs is enabled", config.AutoRebuildGracePeriod, config.Expiry), nil
		}
	}

	if config.EnableDelta {
		deltaRebuildInterval, _ := parseutil.ParseDurationSecond(config.DeltaRebuildInterval)
		if deltaRebuildInterval >= expiry {
			return logical.ErrorResponse("CRL delta rebuild window (%v) must be strictly shorter than CRL expiry (%v) value when delta CRLs are enabled", config.DeltaRebuildInterval, config.Expiry), nil
		}
	}

	if !config.AutoRebuild {
		if config.EnableDelta {
			return logical.ErrorResponse("Delta CRLs cannot be enabled when auto rebuilding is disabled as the complete CRL is always regenerated!"), nil
		}
	}

	entry, err := logical.StorageEntryJSON("config/crl", config)
	if err != nil {
		return nil, err
	}
	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	b.crlBuilder.markConfigDirty()
	b.crlBuilder.reloadConfigIfRequired(sc)

	resp := genResponseFromCrlConfig(config)

	// Note this only affects/happens on the main cluster node, if you need to
	// notify something based on a configuration change on all server types
	// have a look at crlBuilder::reloadConfigIfRequired
	if oldDisable != config.Disable || (oldAutoRebuild && !config.AutoRebuild) || (oldEnableDelta != config.EnableDelta) {
		// It wasn't disabled but now it is (or equivalently, we were set to
		// auto-rebuild and we aren't now or equivalently, we changed our
		// mind about delta CRLs and need a new complete one), rotate the CRLs.
		warnings, crlErr := b.crlBuilder.rebuild(sc, true)
		if crlErr != nil {
			switch crlErr.(type) {
			case errutil.UserError:
				return logical.ErrorResponse("Error during CRL building: %s", crlErr), nil
			default:
				return nil, fmt.Errorf("error encountered during CRL building: %w", crlErr)
			}
		}
		for index, warning := range warnings {
			resp.AddWarning(fmt.Sprintf("Warning %d during CRL rebuild: %v", index+1, warning))
		}
	}

	return resp, nil
}

func genResponseFromCrlConfig(config *crlConfig) *logical.Response {
	return &logical.Response{
		Data: map[string]interface{}{
			"expiry":                        config.Expiry,
			"disable":                       config.Disable,
			"ocsp_disable":                  config.OcspDisable,
			"ocsp_expiry":                   config.OcspExpiry,
			"auto_rebuild":                  config.AutoRebuild,
			"auto_rebuild_grace_period":     config.AutoRebuildGracePeriod,
			"enable_delta":                  config.EnableDelta,
			"delta_rebuild_interval":        config.DeltaRebuildInterval,
			"allow_expired_cert_revocation": config.AllowExpiredCertRevocation,
		},
	}
}

const pathConfigCRLHelpSyn = `
Configure the CRL expiration.
`

const pathConfigCRLHelpDesc = `
This endpoint allows configuration of the CRL lifetime.
`
