// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/armon/go-metrics"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
)

var tidyCancelledError = errors.New("tidy operation cancelled")

type tidyStatusState int

const (
	tidyStatusInactive   tidyStatusState = iota
	tidyStatusStarted                    = iota
	tidyStatusFinished                   = iota
	tidyStatusError                      = iota
	tidyStatusCancelling                 = iota
	tidyStatusCancelled                  = iota
)

type tidyStatus struct {
	// Parameters used to initiate the operation
	safetyBuffer            int
	revokedSafetyBuffer     int
	issuerSafetyBuffer      int
	acmeAccountSafetyBuffer int

	tidyCertStore      bool
	tidyRevokedCerts   bool
	tidyInvalidCerts   bool
	tidyRevokedAssocs  bool
	tidyExpiredIssuers bool
	tidyBackupBundle   bool
	tidyAcme           bool
	pauseDuration      string

	// Page size for list pagination
	pageSize int

	// Status
	state        tidyStatusState
	err          error
	timeStarted  time.Time
	timeFinished time.Time
	message      string

	// These counts use a custom incrementer that grab and release
	// a lock prior to reading.
	certStoreDeletedCount   uint
	revokedCertDeletedCount uint
	missingIssuerCertCount  uint

	acmeAccountsCount        uint
	acmeAccountsRevokedCount uint
	acmeAccountsDeletedCount uint
	acmeOrdersDeletedCount   uint
}

type tidyConfig struct {
	// AutoTidy config
	Enabled  bool          `json:"enabled"`
	Interval time.Duration `json:"interval_duration"`

	// Tidy Operations
	CertStore      bool `json:"tidy_cert_store"`
	RevokedCerts   bool `json:"tidy_revoked_certs"`
	InvalidCerts   bool `json:"tidy_invalid_certs"`
	IssuerAssocs   bool `json:"tidy_revoked_cert_issuer_associations"`
	ExpiredIssuers bool `json:"tidy_expired_issuers"`
	BackupBundle   bool `json:"tidy_move_legacy_ca_bundle"`
	TidyAcme       bool `json:"tidy_acme"`

	// Safety Buffers
	SafetyBuffer            time.Duration  `json:"safety_buffer"`
	RevokedSafetyBuffer     *time.Duration `json:"revoked_safety_buffer"`
	IssuerSafetyBuffer      time.Duration  `json:"issuer_safety_buffer"`
	AcmeAccountSafetyBuffer time.Duration  `json:"acme_account_safety_buffer"`
	PauseDuration           time.Duration  `json:"pause_duration"`

	// Page size for list pagination
	PageSize int `json:"page_size"`

	// Metrics.
	MaintainCount  bool `json:"maintain_stored_certificate_counts"`
	PublishMetrics bool `json:"publish_stored_certificate_count_metrics"`
}

func (tc *tidyConfig) IsAnyTidyEnabled() bool {
	return tc.CertStore || tc.RevokedCerts || tc.InvalidCerts || tc.IssuerAssocs || tc.ExpiredIssuers || tc.BackupBundle || tc.TidyAcme
}

func (tc *tidyConfig) AnyTidyConfig() string {
	return "tidy_cert_store / tidy_revoked_certs / tidy_invalid_certs / tidy_revoked_cert_issuer_associations / tidy_expired_issuers / tidy_move_legacy_ca_bundle / tidy_acme"
}

var defaultTidyConfig = tidyConfig{
	Enabled:                 false,
	Interval:                12 * time.Hour,
	CertStore:               false,
	RevokedCerts:            false,
	InvalidCerts:            false,
	IssuerAssocs:            false,
	ExpiredIssuers:          false,
	BackupBundle:            false,
	TidyAcme:                false,
	SafetyBuffer:            72 * time.Hour,
	IssuerSafetyBuffer:      365 * 24 * time.Hour,
	AcmeAccountSafetyBuffer: 30 * 24 * time.Hour,
	PauseDuration:           0 * time.Second,
	PageSize:                1000,
	MaintainCount:           false,
	PublishMetrics:          false,
}

func pathTidy(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "tidy$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
			OperationVerb:   "tidy",
		},

		Fields: addTidyFields(map[string]*framework.FieldSchema{}),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathTidyWrite,
				Responses: map[int][]framework.Response{
					http.StatusAccepted: {{
						Description: "Accepted",
						Fields:      map[string]*framework.FieldSchema{},
					}},
				},
				ForwardPerformanceStandby: true,
			},
		},
		HelpSynopsis:    pathTidyHelpSyn,
		HelpDescription: pathTidyHelpDesc,
	}
}

func pathTidyCancel(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "tidy-cancel$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
			OperationVerb:   "tidy",
			OperationSuffix: "cancel",
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathTidyCancelWrite,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"safety_buffer": {
								Type:        framework.TypeInt,
								Description: `Safety buffer time duration`,
								Required:    false,
							},
							"revoked_safety_buffer": {
								Type:        framework.TypeInt,
								Description: `Revoked safety buffer time duration`,
								Required:    false,
							},
							"issuer_safety_buffer": {
								Type:        framework.TypeInt,
								Description: `Issuer safety buffer`,
								Required:    false,
							},
							"tidy_cert_store": {
								Type:        framework.TypeBool,
								Description: `Tidy certificate store`,
								Required:    false,
							},
							"tidy_revoked_certs": {
								Type:        framework.TypeBool,
								Description: `Tidy revoked certificates`,
								Required:    false,
							},
							"tidy_invalid_certs": {
								Type:        framework.TypeBool,
								Description: `Tidy invalid certificates`,
								Required:    false,
							},
							"tidy_revoked_cert_issuer_associations": {
								Type:        framework.TypeBool,
								Description: `Tidy revoked certificate issuer associations`,
								Required:    false,
							},
							"tidy_acme": {
								Type:        framework.TypeBool,
								Description: `Tidy Unused Acme Accounts, and Orders`,
								Required:    false,
							},
							"acme_account_safety_buffer": {
								Type:        framework.TypeInt,
								Description: `Safety buffer after creation after which accounts lacking orders are revoked`,
								Required:    false,
							},
							"tidy_expired_issuers": {
								Type:        framework.TypeBool,
								Description: `Tidy expired issuers`,
								Required:    false,
							},
							"pause_duration": {
								Type:        framework.TypeString,
								Description: `Duration to pause between tidying certificates`,
								Required:    false,
							},
							"page_size": {
								Type:        framework.TypeInt,
								Description: `The number of certificates per page for list pagination`,
								Required:    false,
							},
							"state": {
								Type:        framework.TypeString,
								Description: `One of Inactive, Running, Finished, or Error`,
								Required:    false,
							},
							"error": {
								Type:        framework.TypeString,
								Description: `The error message`,
								Required:    false,
							},
							"time_started": {
								Type:        framework.TypeString,
								Description: `Time the operation started`,
								Required:    false,
							},
							"time_finished": {
								Type:        framework.TypeString,
								Description: `Time the operation finished`,
								Required:    false,
							},
							"last_auto_tidy_finished": {
								Type:        framework.TypeString,
								Description: `Time the last auto-tidy operation finished`,
								Required:    true,
							},
							"message": {
								Type:        framework.TypeString,
								Description: `Message of the operation`,
								Required:    false,
							},
							"cert_store_deleted_count": {
								Type:        framework.TypeInt,
								Description: `The number of certificate storage entries deleted`,
								Required:    false,
							},
							"revoked_cert_deleted_count": {
								Type:        framework.TypeInt,
								Description: `The number of revoked certificate entries deleted`,
								Required:    false,
							},
							"current_cert_store_count": {
								Type:        framework.TypeInt,
								Description: `The number of revoked certificate entries deleted`,
								Required:    false,
							},
							"current_revoked_cert_count": {
								Type:        framework.TypeInt,
								Description: `The number of revoked certificate entries deleted`,
								Required:    false,
							},
							"missing_issuer_cert_count": {
								Type:     framework.TypeInt,
								Required: false,
							},
							"tidy_move_legacy_ca_bundle": {
								Type:     framework.TypeBool,
								Required: false,
							},
							"internal_backend_uuid": {
								Type:     framework.TypeString,
								Required: false,
							},
							"total_acme_account_count": {
								Type:        framework.TypeInt,
								Description: `Total number of acme accounts iterated over`,
								Required:    false,
							},
							"acme_account_deleted_count": {
								Type:        framework.TypeInt,
								Description: `The number of revoked acme accounts removed`,
								Required:    false,
							},
							"acme_account_revoked_count": {
								Type:        framework.TypeInt,
								Description: `The number of unused acme accounts revoked`,
								Required:    false,
							},
							"acme_orders_deleted_count": {
								Type:        framework.TypeInt,
								Description: `The number of expired, unused acme orders removed`,
								Required:    false,
							},
						},
					}},
				},
				ForwardPerformanceStandby: true,
			},
		},
		HelpSynopsis:    pathTidyCancelHelpSyn,
		HelpDescription: pathTidyCancelHelpDesc,
	}
}

func pathTidyStatus(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "tidy-status$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
			OperationVerb:   "tidy",
			OperationSuffix: "status",
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathTidyStatusRead,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"safety_buffer": {
								Type:        framework.TypeInt,
								Description: `Safety buffer time duration`,
								Required:    true,
							},
							"revoked_safety_buffer": {
								Type:        framework.TypeInt,
								Description: `Revoked safety buffer time duration`,
								Required:    true,
							},
							"issuer_safety_buffer": {
								Type:        framework.TypeInt,
								Description: `Issuer safety buffer`,
								Required:    true,
							},
							"acme_account_safety_buffer": {
								Type:        framework.TypeInt,
								Description: `Safety buffer after creation after which accounts lacking orders are revoked`,
								Required:    false,
							},
							"tidy_cert_store": {
								Type:        framework.TypeBool,
								Description: `Tidy certificate store`,
								Required:    true,
							},
							"tidy_revoked_certs": {
								Type:        framework.TypeBool,
								Description: `Tidy revoked certificates`,
								Required:    true,
							},
							"tidy_invalid_certs": {
								Type:        framework.TypeBool,
								Description: `Tidy invalid certificates`,
								Required:    true,
							},
							"tidy_revoked_cert_issuer_associations": {
								Type:        framework.TypeBool,
								Description: `Tidy revoked certificate issuer associations`,
								Required:    true,
							},
							"tidy_expired_issuers": {
								Type:        framework.TypeBool,
								Description: `Tidy expired issuers`,
								Required:    true,
							},
							"tidy_acme": {
								Type:        framework.TypeBool,
								Description: `Tidy Unused Acme Accounts, and Orders`,
								Required:    true,
							},
							"pause_duration": {
								Type:        framework.TypeString,
								Description: `Duration to pause between tidying certificates`,
								Required:    true,
							},
							"page_size": {
								Type:        framework.TypeInt,
								Description: `The number of certificates per page for list pagination`,
								Required:    false,
							},
							"state": {
								Type:        framework.TypeString,
								Description: `One of Inactive, Running, Finished, or Error`,
								Required:    true,
							},
							"error": {
								Type:        framework.TypeString,
								Description: `The error message`,
								Required:    true,
							},
							"time_started": {
								Type:        framework.TypeString,
								Description: `Time the operation started`,
								Required:    true,
							},
							"time_finished": {
								Type:        framework.TypeString,
								Description: `Time the operation finished`,
								Required:    false,
							},
							"last_auto_tidy_finished": {
								Type:        framework.TypeString,
								Description: `Time the last auto-tidy operation finished`,
								Required:    true,
							},
							"message": {
								Type:        framework.TypeString,
								Description: `Message of the operation`,
								Required:    true,
							},
							"cert_store_deleted_count": {
								Type:        framework.TypeInt,
								Description: `The number of certificate storage entries deleted`,
								Required:    true,
							},
							"revoked_cert_deleted_count": {
								Type:        framework.TypeInt,
								Description: `The number of revoked certificate entries deleted`,
								Required:    true,
							},
							"current_cert_store_count": {
								Type:        framework.TypeInt,
								Description: `The number of revoked certificate entries deleted`,
								Required:    true,
							},
							"current_revoked_cert_count": {
								Type:        framework.TypeInt,
								Description: `The number of revoked certificate entries deleted`,
								Required:    true,
							},
							"tidy_move_legacy_ca_bundle": {
								Type:     framework.TypeBool,
								Required: true,
							},
							"missing_issuer_cert_count": {
								Type:     framework.TypeInt,
								Required: true,
							},
							"internal_backend_uuid": {
								Type:     framework.TypeString,
								Required: true,
							},
							"total_acme_account_count": {
								Type:        framework.TypeInt,
								Description: `Total number of acme accounts iterated over`,
								Required:    false,
							},
							"acme_account_deleted_count": {
								Type:        framework.TypeInt,
								Description: `The number of revoked acme accounts removed`,
								Required:    false,
							},
							"acme_account_revoked_count": {
								Type:        framework.TypeInt,
								Description: `The number of unused acme accounts revoked`,
								Required:    false,
							},
							"acme_orders_deleted_count": {
								Type:        framework.TypeInt,
								Description: `The number of expired, unused acme orders removed`,
								Required:    false,
							},
						},
					}},
				},
				ForwardPerformanceStandby: true,
			},
		},
		HelpSynopsis:    pathTidyStatusHelpSyn,
		HelpDescription: pathTidyStatusHelpDesc,
	}
}

func pathConfigAutoTidy(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/auto-tidy",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
		},
		Fields: addTidyFields(map[string]*framework.FieldSchema{
			"enabled": {
				Type:        framework.TypeBool,
				Description: `Set to true to enable automatic tidy operations.`,
			},
			"interval_duration": {
				Type:        framework.TypeDurationSecond,
				Description: `Interval at which to run an auto-tidy operation. This is the time between tidy invocations (after one finishes to the start of the next). Running a manual tidy will reset this duration.`,
				Default:     int(defaultTidyConfig.Interval / time.Second), // TypeDurationSecond currently requires the default to be an int.
			},
			"maintain_stored_certificate_counts": {
				Type: framework.TypeBool,
				Description: `This configures whether stored certificates
are counted upon initialization of the backend, and whether during
normal operation, a running count of certificates stored is maintained.`,
				Default: false,
			},
			"publish_stored_certificate_count_metrics": {
				Type: framework.TypeBool,
				Description: `This configures whether the stored certificate
count is published to the metrics consumer.  It does not affect if the
stored certificate count is maintained, and if maintained, it will be
available on the tidy-status endpoint.`,
				Default: false,
			},
		}),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigAutoTidyRead,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "auto-tidy-configuration",
				},
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"enabled": {
								Type:        framework.TypeBool,
								Description: `Specifies whether automatic tidy is enabled or not`,
								Required:    true,
							},
							"interval_duration": {
								Type:        framework.TypeInt,
								Description: `Specifies the duration between automatic tidy operation`,
								Required:    true,
							},
							"tidy_cert_store": {
								Type:        framework.TypeBool,
								Description: `Specifies whether to tidy up the certificate store`,
								Required:    true,
							},
							"tidy_revoked_certs": {
								Type:        framework.TypeBool,
								Description: `Specifies whether to remove all revoked and expired certificates from storage`,
								Required:    true,
							},
							"tidy_invalid_certs": {
								Type:        framework.TypeBool,
								Description: `Specifies whether to remove invalid certificates from storage`,
								Required:    true,
							},
							"tidy_revoked_cert_issuer_associations": {
								Type:        framework.TypeBool,
								Description: `Specifies whether to associate revoked certificates with their corresponding issuers`,
								Required:    true,
							},
							"tidy_expired_issuers": {
								Type:        framework.TypeBool,
								Description: `Specifies whether tidy expired issuers`,
								Required:    true,
							},
							"tidy_acme": {
								Type:        framework.TypeBool,
								Description: `Tidy Unused Acme Accounts, and Orders`,
								Required:    true,
							},
							"safety_buffer": {
								Type:        framework.TypeInt,
								Description: `Safety buffer time duration`,
								Required:    true,
							},
							"revoked_safety_buffer": {
								Type:        framework.TypeInt,
								Description: `Revoked safety buffer time duration`,
								Required:    true,
							},
							"issuer_safety_buffer": {
								Type:        framework.TypeInt,
								Description: `Issuer safety buffer`,
								Required:    true,
							},
							"acme_account_safety_buffer": {
								Type:        framework.TypeInt,
								Description: `Safety buffer after creation after which accounts lacking orders are revoked`,
								Required:    false,
							},
							"pause_duration": {
								Type:        framework.TypeString,
								Description: `Duration to pause between tidying certificates`,
								Required:    true,
							},
							"page_size": {
								Type:        framework.TypeInt,
								Description: `The number of certificates per page for list pagination`,
								Required:    false,
							},
							"tidy_move_legacy_ca_bundle": {
								Type:     framework.TypeBool,
								Required: true,
							},
							"publish_stored_certificate_count_metrics": {
								Type:     framework.TypeBool,
								Required: true,
							},
							"maintain_stored_certificate_counts": {
								Type:     framework.TypeBool,
								Required: true,
							},
						},
					}},
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigAutoTidyWrite,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "configure",
					OperationSuffix: "auto-tidy",
				},
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"enabled": {
								Type:        framework.TypeBool,
								Description: `Specifies whether automatic tidy is enabled or not`,
								Required:    true,
							},
							"interval_duration": {
								Type:        framework.TypeInt,
								Description: `Specifies the duration between automatic tidy operation`,
								Required:    true,
							},
							"tidy_cert_store": {
								Type:        framework.TypeBool,
								Description: `Specifies whether to tidy up the certificate store`,
								Required:    true,
							},
							"tidy_revoked_certs": {
								Type:        framework.TypeBool,
								Description: `Specifies whether to remove all revoked and expired certificates from storage`,
								Required:    true,
							},
							"tidy_invalid_certs": {
								Type:        framework.TypeBool,
								Description: `Specifies whether to remove invalid certificates from storage`,
								Required:    true,
							},
							"tidy_revoked_cert_issuer_associations": {
								Type:        framework.TypeBool,
								Description: `Specifies whether to associate revoked certificates with their corresponding issuers`,
								Required:    true,
							},
							"tidy_expired_issuers": {
								Type:        framework.TypeBool,
								Description: `Specifies whether tidy expired issuers`,
								Required:    true,
							},
							"tidy_acme": {
								Type:        framework.TypeBool,
								Description: `Tidy Unused Acme Accounts, and Orders`,
								Required:    true,
							},
							"safety_buffer": {
								Type:        framework.TypeInt,
								Description: `Safety buffer time duration`,
								Required:    true,
							},
							"revoked_safety_buffer": {
								Type:        framework.TypeInt,
								Description: `Revoked safety buffer time duration`,
								Required:    true,
							},
							"issuer_safety_buffer": {
								Type:        framework.TypeInt,
								Description: `Issuer safety buffer`,
								Required:    true,
							},
							"acme_account_safety_buffer": {
								Type:        framework.TypeInt,
								Description: `Safety buffer after creation after which accounts lacking orders are revoked`,
								Required:    true,
							},
							"pause_duration": {
								Type:        framework.TypeString,
								Description: `Duration to pause between tidying certificates`,
								Required:    true,
							},
							"page_size": {
								Type:        framework.TypeInt,
								Description: `The number of certificates per page for list pagination`,
								Required:    false,
							},
							"tidy_move_legacy_ca_bundle": {
								Type:     framework.TypeBool,
								Required: true,
							},
							"publish_stored_certificate_count_metrics": {
								Type:     framework.TypeBool,
								Required: true,
							},
							"maintain_stored_certificate_counts": {
								Type:     framework.TypeBool,
								Required: true,
							},
						},
					}},
				},
				// Read more about why these flags are set in backend.go.
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},
		HelpSynopsis:    pathConfigAutoTidySyn,
		HelpDescription: pathConfigAutoTidyDesc,
	}
}

func (b *backend) pathTidyWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	safetyBuffer := d.Get("safety_buffer").(int)
	revokedSafetyBuffer := 0
	if revokedSafetyBufferRaw, ok := d.GetOk("revoked_safety_buffer"); ok {
		revokedSafetyBuffer = revokedSafetyBufferRaw.(int)
	} else {
		// Default to safety buffer
		revokedSafetyBuffer = safetyBuffer
	}
	tidyCertStore := d.Get("tidy_cert_store").(bool)
	tidyRevokedCerts := d.Get("tidy_revoked_certs").(bool) || d.Get("tidy_revocation_list").(bool)
	tidyInvalidCerts := d.Get("tidy_invalid_certs").(bool)
	tidyRevokedAssocs := d.Get("tidy_revoked_cert_issuer_associations").(bool)
	tidyExpiredIssuers := d.Get("tidy_expired_issuers").(bool)
	tidyBackupBundle := d.Get("tidy_move_legacy_ca_bundle").(bool)
	issuerSafetyBuffer := d.Get("issuer_safety_buffer").(int)
	pauseDurationStr := d.Get("pause_duration").(string)
	pageSize := d.Get("page_size").(int)
	pauseDuration := 0 * time.Second
	tidyAcme := d.Get("tidy_acme").(bool)
	acmeAccountSafetyBuffer := d.Get("acme_account_safety_buffer").(int)

	if safetyBuffer < 1 {
		return logical.ErrorResponse("safety_buffer must be greater than zero"), nil
	}

	if revokedSafetyBuffer < 1 {
		return logical.ErrorResponse("revokedSafetyBuffer must be greater than zero"), nil
	}

	if issuerSafetyBuffer < 1 {
		return logical.ErrorResponse("issuer_safety_buffer must be greater than zero"), nil
	}

	if acmeAccountSafetyBuffer < 1 {
		return logical.ErrorResponse("acme_account_safety_buffer must be greater than zero"), nil
	}

	if pauseDurationStr != "" {
		var err error
		pauseDuration, err = parseutil.ParseDurationSecond(pauseDurationStr)
		if err != nil {
			return logical.ErrorResponse("Error parsing pause_duration: %v", err), nil
		}

		if pauseDuration < (0 * time.Second) {
			return logical.ErrorResponse("received invalid, negative pause_duration"), nil
		}
	}

	if pageSize > 0 && pageSize < 5 {
		return logical.ErrorResponse("page_size must be greater than five"), nil
	}

	bufferDuration := time.Duration(safetyBuffer) * time.Second
	revokedBufferDuration := time.Duration(revokedSafetyBuffer) * time.Second
	issuerBufferDuration := time.Duration(issuerSafetyBuffer) * time.Second
	acmeAccountSafetyBufferDuration := time.Duration(acmeAccountSafetyBuffer) * time.Second

	// Manual run with constructed configuration.
	config := &tidyConfig{
		Enabled:                 true,
		Interval:                0 * time.Second,
		CertStore:               tidyCertStore,
		RevokedCerts:            tidyRevokedCerts,
		InvalidCerts:            tidyInvalidCerts,
		IssuerAssocs:            tidyRevokedAssocs,
		ExpiredIssuers:          tidyExpiredIssuers,
		BackupBundle:            tidyBackupBundle,
		SafetyBuffer:            bufferDuration,
		RevokedSafetyBuffer:     &revokedBufferDuration,
		IssuerSafetyBuffer:      issuerBufferDuration,
		PauseDuration:           pauseDuration,
		PageSize:                pageSize,
		TidyAcme:                tidyAcme,
		AcmeAccountSafetyBuffer: acmeAccountSafetyBufferDuration,
	}

	if !atomic.CompareAndSwapUint32(b.tidyCASGuard, 0, 1) {
		resp := &logical.Response{}
		resp.AddWarning("Tidy operation already in progress.")
		return resp, nil
	}

	// Tests using framework will screw up the storage so make a locally
	// scoped req to hold a reference
	req = &logical.Request{
		Storage: req.Storage,
	}

	// Mark the last tidy operation as relatively recent, to ensure we don't
	// try to trigger the periodic function.
	b.tidyStatusLock.Lock()
	b.lastTidy = time.Now()
	b.tidyStatusLock.Unlock()

	// Kick off the actual tidy.
	b.startTidyOperation(req, config)

	resp := &logical.Response{}
	if !config.IsAnyTidyEnabled() {
		resp.AddWarning("Manual tidy requested but no tidy operations were set. Enable at least one tidy operation to be run (" + config.AnyTidyConfig() + ").")
	} else {
		resp.AddWarning("Tidy operation successfully started. Any information from the operation will be printed to OpenBao's server logs.")
	}

	return logical.RespondWithStatusCode(resp, req, http.StatusAccepted)
}

func (b *backend) startTidyOperation(req *logical.Request, config *tidyConfig) {
	go func() {
		atomic.StoreUint32(b.tidyCancelCAS, 0)
		defer atomic.StoreUint32(b.tidyCASGuard, 0)

		b.tidyStatusStart(config)

		// Don't cancel when the original client request goes away.
		ctx := context.Background()

		logger := b.Logger().Named("tidy")

		doTidy := func() error {
			var revokedDeleted uint
			var rebuildCRL bool

			if config.CertStore || config.InvalidCerts {
				deleted, err := b.doTidyCertStore(ctx, req, logger, config)
				if err != nil {
					return err
				}
				rebuildCRL = rebuildCRL || (deleted > 0)
				revokedDeleted = deleted
			}

			// Check for cancel before continuing.
			if atomic.CompareAndSwapUint32(b.tidyCancelCAS, 1, 0) {
				return tidyCancelledError
			}

			if config.RevokedCerts || config.IssuerAssocs || config.InvalidCerts {
				rebuild, err := b.doTidyRevocationStore(ctx, req, logger, config, revokedDeleted)
				if err != nil {
					return err
				}
				rebuildCRL = rebuildCRL || rebuild
			}

			// Check for cancel before continuing.
			if atomic.CompareAndSwapUint32(b.tidyCancelCAS, 1, 0) {
				return tidyCancelledError
			}

			if rebuildCRL {
				if err := b.doTidyRebuildCRL(ctx, req, logger, config); err != nil {
					return err
				}
			}

			// Check for cancel before continuing.
			if atomic.CompareAndSwapUint32(b.tidyCancelCAS, 1, 0) {
				return tidyCancelledError
			}

			if config.ExpiredIssuers {
				if err := b.doTidyExpiredIssuers(ctx, req, logger, config); err != nil {
					return err
				}
			}

			// Check for cancel before continuing.
			if atomic.CompareAndSwapUint32(b.tidyCancelCAS, 1, 0) {
				return tidyCancelledError
			}

			if config.BackupBundle {
				if err := b.doTidyMoveCABundle(ctx, req, logger, config); err != nil {
					return err
				}
			}

			// Check for cancel before continuing.
			if atomic.CompareAndSwapUint32(b.tidyCancelCAS, 1, 0) {
				return tidyCancelledError
			}

			if config.TidyAcme {
				if err := b.doTidyAcme(ctx, req, logger, config); err != nil {
					return err
				}
			}

			return nil
		}

		if err := doTidy(); err != nil {
			logger.Error("error running tidy", "error", err)
			b.tidyStatusStop(err)
		} else {
			b.tidyStatusStop(nil)

			// Since the tidy operation finished without an error, we don't
			// really want to start another tidy right away (if the interval
			// is too short). So mark the last tidy as now.
			b.tidyStatusLock.Lock()
			b.lastTidy = time.Now()
			b.tidyStatusLock.Unlock()
		}
	}()
}

func (b *backend) doTidyCertStore(ctx context.Context, req *logical.Request, logger hclog.Logger, config *tidyConfig) (uint, error) {
	revokedSafetyBuffer := config.SafetyBuffer
	if config.RevokedSafetyBuffer != nil {
		revokedSafetyBuffer = *config.RevokedSafetyBuffer
	}

	// Total number of certificates in storage
	var totalSerialCount int
	// Total number of deleted revoked certificates in this tidy call
	var revokedDeleted uint
	haveWarned := false

	// Define item-level callback that processes each certificate entry
	itemCallback := func(page int, index int, serial string) (bool, error) {
		b.tidyStatusMessage(fmt.Sprintf("Tidying certificate store: checking entry %d of %d on current page; total certs checked: %d", index, config.PageSize, totalSerialCount+index))
		metrics.SetGauge([]string{"secrets", "pki", "tidy", "cert_store_current_entry"}, float32(totalSerialCount+index))

		// Check for cancel before continuing
		if atomic.CompareAndSwapUint32(b.tidyCancelCAS, 1, 0) {
			return false, tidyCancelledError
		}

		// Check for pause duration to reduce resource consumption
		if config.PauseDuration > (0 * time.Second) {
			time.Sleep(config.PauseDuration)
		}

		certEntry, err := req.Storage.Get(ctx, "certs/"+serial)
		if err != nil {
			return false, fmt.Errorf("error fetching certificate %q: %w", serial, err)
		}

		if certEntry == nil {
			logger.Warn("certificate entry is nil; tidying up since it is no longer useful for any server operations", "serial", serial)
			if err := req.Storage.Delete(ctx, "certs/"+serial); err != nil {
				return false, fmt.Errorf("error deleting nil entry with serial %s: %w", serial, err)
			}
			b.tidyStatusIncCertStoreCount()
			return true, nil
		}

		if len(certEntry.Value) == 0 {
			logger.Warn("certificate entry has no value; tidying up since it is no longer useful for any server operations", "serial", serial)
			if err := req.Storage.Delete(ctx, "certs/"+serial); err != nil {
				return false, fmt.Errorf("error deleting entry with nil value with serial %s: %w", serial, err)
			}
			b.tidyStatusIncCertStoreCount()
			return true, nil
		}

		cert, err := x509.ParseCertificate(certEntry.Value)
		if err != nil {
			// only log warning once
			if !haveWarned {
				msg := "Unable to parse stored certificate. Other invalid certificates may exist; "
				if config.InvalidCerts {
					msg += "tidying up since it is not usable."
				} else {
					msg += "tidy by enabling tidy_invalid_certs=true."
				}
				logger.Warn(msg, "serial", serial, "err", err)
				haveWarned = true
			}

			// if tidy_invalid_certs enabled, delete invalid cert. Because
			// we're cleaning up revoked certs later by virtue of
			// config.InvalidCerts=true, we can skip deleting revoked certs
			// here.
			if config.InvalidCerts {
				if err := req.Storage.Delete(ctx, "certs/"+serial); err != nil {
					return false, fmt.Errorf("error deleting invalid certificate %s: %w", serial, err)
				}
				b.tidyStatusIncCertStoreCount()
			}

			return true, nil
		}

		// We could be exclusively looking for invalid certificates; skip
		// fetching a known-good revocation entry here if so. This also lets
		// us avoid guarding each deletion check below.
		if !config.CertStore {
			return true, nil
		}

		// Check if a revocation entry exists for this cert; if so, use the
		// appropriate entry.
		revokedResp, err := req.Storage.Get(ctx, "revoked/"+serial)
		if err != nil {
			return false, fmt.Errorf("error fetching revocation status of serial %q from storage: %w", serial, err)
		}

		if revokedResp == nil && time.Since(cert.NotAfter) > config.SafetyBuffer {
			if err := req.Storage.Delete(ctx, "certs/"+serial); err != nil {
				return false, fmt.Errorf("error deleting serial %q from storage: %w", serial, err)
			}
			b.tidyStatusIncCertStoreCount()
		} else if revokedResp != nil && time.Since(cert.NotAfter) > revokedSafetyBuffer {
			if err := req.Storage.Delete(ctx, "certs/"+serial); err != nil {
				return false, fmt.Errorf("error deleting serial %q from store when tidying revoked: %w", serial, err)
			}
			// Only tidy revoked certs if requested.
			if config.RevokedCerts {
				if err := req.Storage.Delete(ctx, "revoked/"+serial); err != nil {
					return false, fmt.Errorf("error deleting serial %q from revoked list: %w", serial, err)
				}
				revokedDeleted++
				b.tidyStatusIncRevokedCertCount()
			}
			b.tidyStatusIncCertStoreCount()
		}
		return true, nil
	}

	// Define batch-level callback that updates cumulative count after processing the page
	batchCallback := func(page int, entries []string) (bool, error) {
		totalSerialCount += len(entries)
		return true, nil
	}

	// Use HandleListPage to process paginated results
	err := logical.HandleListPage(ctx, req.Storage, "certs/", config.PageSize, itemCallback, batchCallback)
	if err != nil {
		return 0, err
	}

	// Set metrics for total certificates and remaining certificates
	b.tidyStatusLock.RLock()
	metrics.SetGauge([]string{"secrets", "pki", "tidy", "cert_store_total_entries"}, float32(totalSerialCount))
	metrics.SetGauge([]string{"secrets", "pki", "tidy", "cert_store_total_entries_remaining"}, float32(uint(totalSerialCount)-b.tidyStatus.certStoreDeletedCount))
	b.tidyStatusLock.RUnlock()

	return revokedDeleted, nil
}

func (b *backend) doTidyRevocationStore(ctx context.Context, req *logical.Request, logger hclog.Logger, config *tidyConfig, revokedDeleted uint) (bool, error) {
	b.revokeStorageLock.Lock()
	defer b.revokeStorageLock.Unlock()

	// Fetch and parse our issuers so we can associate them if necessary.
	sc := b.makeStorageContext(ctx, req.Storage)
	issuerIDCertMap, err := fetchIssuerMapForRevocationChecking(sc)
	if err != nil {
		return false, err
	}

	revokedSafetyBuffer := config.SafetyBuffer
	if config.RevokedSafetyBuffer != nil {
		revokedSafetyBuffer = *config.RevokedSafetyBuffer
	}

	// Number of certificates on current page. This value is <= PageSize.
	var lenSerials int
	// Total number of revoked certificates in storage
	var totalRevokedSerialCount int = 0
	// Total number of deleted revoked certificates in this tidy call
	var revokedDeletedCount int = 0

	var revInfo revocationInfo
	haveWarned := false
	rebuildCRL := false
	fixedIssuers := 0

	// Define item-level callback that processes each revoked cert entry
	itemCallback := func(page int, index int, serial string) (bool, error) {
		b.tidyStatusMessage(fmt.Sprintf("Tidying revoked certificates: checking certificate %d of %d on current page; total revoked certs checked: %d", index, lenSerials, int(totalRevokedSerialCount)+index))
		metrics.SetGauge([]string{"secrets", "pki", "tidy", "revoked_cert_current_entry"}, float32(int(totalRevokedSerialCount)+index))

		// Check for cancel before continuing.
		if atomic.CompareAndSwapUint32(b.tidyCancelCAS, 1, 0) {
			return false, tidyCancelledError
		}

		// Check for pause duration to reduce resource consumption.
		if config.PauseDuration > (0 * time.Second) {
			b.revokeStorageLock.Unlock()
			time.Sleep(config.PauseDuration)
			b.revokeStorageLock.Lock()
		}

		revokedEntry, err := req.Storage.Get(ctx, "revoked/"+serial)
		if err != nil {
			return false, fmt.Errorf("unable to fetch revoked cert with serial %q: %w", serial, err)
		}

		if revokedEntry == nil {
			if !haveWarned {
				logger.Warn("Revoked entry is nil. Other invalid entries may exist; tidying up since it is no longer useful for any server operations.", "serial", serial)
			}
			if err := req.Storage.Delete(ctx, "revoked/"+serial); err != nil {
				return false, fmt.Errorf("error deleting nil revoked entry with serial %s: %w", serial, err)
			}
			b.tidyStatusIncRevokedCertCount()
			revokedDeletedCount += 1
			return true, nil
		}

		if len(revokedEntry.Value) == 0 {
			if !haveWarned {
				logger.Warn("Revoked entry has nil value. Other invalid entries may exist; tidying up since it is no longer useful for any server operations", "serial", serial)
			}
			if err := req.Storage.Delete(ctx, "revoked/"+serial); err != nil {
				return false, fmt.Errorf("error deleting revoked entry with nil value with serial %s: %w", serial, err)
			}
			b.tidyStatusIncRevokedCertCount()
			revokedDeletedCount += 1
			return true, nil
		}

		err = revokedEntry.DecodeJSON(&revInfo)
		if err != nil {
			return false, fmt.Errorf("error decoding revocation entry for serial %q: %w", serial, err)
		}

		revokedCert, err := x509.ParseCertificate(revInfo.CertificateBytes)
		if err != nil {
			// only log warning once
			if !haveWarned {
				msg := "Unable to parse revoked certificate. Other invalid certificates may exist; "
				if config.InvalidCerts {
					msg += "tidying up since it is not usable."
				} else {
					msg += "tidy by enabling tidy_invalid_certs=true."
				}
				logger.Warn(msg, "serial", serial, "err", err)
				haveWarned = true
			}

			// If tidy_invalid_certs enabled, delete invalid revoked cert.
			// We know we've already deleted the invalid cert entry via
			// doTidyCertStore(...) earlier so don't bother deleting that
			// too.
			if config.InvalidCerts {
				if err := req.Storage.Delete(ctx, "revoked/"+serial); err != nil {
					return false, fmt.Errorf("error deleting invalid revoked certificate %s: %w", serial, err)
				}
				b.tidyStatusIncRevokedCertCount()
				revokedDeletedCount += 1
			}

			return true, nil
		}

		// Tidy operations over revoked certs should execute prior to
		// tidyRevokedCerts as that may remove the entry. If that happens,
		// we won't persist the revInfo changes (as it was deleted instead).
		var storeCert bool = false
		if config.IssuerAssocs {
			if !isRevInfoIssuerValid(&revInfo, issuerIDCertMap) {
				b.tidyStatusIncMissingIssuerCertCount()
				revInfo.CertificateIssuer = issuerID("")
				storeCert = true
				if associateRevokedCertWithIsssuer(&revInfo, revokedCert, issuerIDCertMap) {
					fixedIssuers += 1
				}
			}
		}

		if config.RevokedCerts {
			// Only remove the entries from revoked/ and certs/ if we're
			// past its NotAfter value. This is because we use the
			// information on revoked/ to build the CRL and the
			// information on certs/ for lookup.

			if time.Since(revokedCert.NotAfter) > revokedSafetyBuffer {
				if err := req.Storage.Delete(ctx, "revoked/"+serial); err != nil {
					return false, fmt.Errorf("error deleting serial %q from revoked list: %w", serial, err)
				}
				if err := req.Storage.Delete(ctx, "certs/"+serial); err != nil {
					return false, fmt.Errorf("error deleting serial %q from store when tidying revoked: %w", serial, err)
				}
				rebuildCRL = true
				storeCert = false
				b.tidyStatusIncRevokedCertCount()
				revokedDeletedCount += 1
			}
		}

		// If the entry wasn't removed but was otherwise modified,
		// go ahead and write it back out.
		if storeCert {
			revokedEntry, err = logical.StorageEntryJSON("revoked/"+serial, revInfo)
			if err != nil {
				return false, fmt.Errorf("error building entry to persist changes to serial %v from revoked list: %w", serial, err)
			}

			err = req.Storage.Put(ctx, revokedEntry)
			if err != nil {
				return false, fmt.Errorf("error persisting changes to serial %v from revoked list: %w", serial, err)
			}
		}
		return true, nil
	}

	// Define batch-level callback for updating cumulative count after processing the page
	batchCallback := func(page int, entries []string) (bool, error) {
		totalRevokedSerialCount += len(entries)
		return true, nil
	}

	// Use handleListPage to process paginated results
	err = logical.HandleListPage(ctx, req.Storage, "revoked/", config.PageSize, itemCallback, batchCallback)
	if err != nil {
		return false, err
	}

	totalRevokedSerialCount += int(revokedDeleted)
	revokedDeletedCount += int(revokedDeleted)

	b.tidyStatusLock.RLock()
	metrics.SetGauge([]string{"secrets", "pki", "tidy", "revoked_cert_total_entries"}, float32(totalRevokedSerialCount))
	metrics.SetGauge([]string{"secrets", "pki", "tidy", "revoked_cert_total_entries_remaining"}, float32(totalRevokedSerialCount-revokedDeletedCount))
	metrics.SetGauge([]string{"secrets", "pki", "tidy", "revoked_cert_entries_incorrect_issuers"}, float32(b.tidyStatus.missingIssuerCertCount))
	metrics.SetGauge([]string{"secrets", "pki", "tidy", "revoked_cert_entries_fixed_issuers"}, float32(fixedIssuers))
	b.tidyStatusLock.RUnlock()

	return rebuildCRL, nil
}

func (b *backend) doTidyRebuildCRL(ctx context.Context, req *logical.Request, logger hclog.Logger, config *tidyConfig) error {
	// Expired certificates isn't generally an important
	// reason to trigger a CRL rebuild for. Check if
	// automatic CRL rebuilds have been enabled and defer
	// the rebuild if so.
	sc := b.makeStorageContext(ctx, req.Storage)
	crlConfig, err := sc.getRevocationConfig()
	if err != nil {
		return err
	}

	if !crlConfig.AutoRebuild {
		warnings, err := b.crlBuilder.rebuild(sc, false)
		if err != nil {
			return err
		}
		if len(warnings) > 0 {
			msg := "During rebuild of CRL for tidy, got the following warnings:"
			for index, warning := range warnings {
				msg = fmt.Sprintf("%v\n %d. %v", msg, index+1, warning)
			}
			b.Logger().Warn(msg)
		}
	}

	return nil
}

func (b *backend) doTidyExpiredIssuers(ctx context.Context, req *logical.Request, logger hclog.Logger, config *tidyConfig) error {
	// We do not support cancelling within the expired issuers operation.
	// Any cancellation will occur before or after this operation.

	if b.System().ReplicationState().HasState(consts.ReplicationDRSecondary|consts.ReplicationPerformanceStandby) ||
		(!b.System().LocalMount() && b.System().ReplicationState().HasState(consts.ReplicationPerformanceSecondary)) {
		b.Logger().Debug("skipping expired issuer tidy as we're not on the primary or secondary with a local mount")
		return nil
	}

	// Short-circuit to avoid having to deal with the legacy mounts. While we
	// could handle this case and remove these issuers, its somewhat
	// unexpected behavior and we'd prefer to finish the migration first.
	if b.useLegacyBundleCaStorage() {
		return nil
	}

	b.issuersLock.Lock()
	defer b.issuersLock.Unlock()

	// Fetch and parse our issuers so we have their expiration date.
	sc := b.makeStorageContext(ctx, req.Storage)
	issuerIDCertMap, err := fetchIssuerMapForRevocationChecking(sc)
	if err != nil {
		return err
	}

	// Fetch the issuer config to find the default; we don't want to remove
	// the current active issuer automatically.
	iConfig, err := sc.getIssuersConfig()
	if err != nil {
		return err
	}

	// We want certificates which have expired before this date by a given
	// safety buffer.
	rebuildChainsAndCRL := false

	for issuer, cert := range issuerIDCertMap {
		if time.Since(cert.NotAfter) <= config.IssuerSafetyBuffer {
			continue
		}

		entry, err := sc.fetchIssuerById(issuer)
		if err != nil {
			return nil
		}

		// This issuer's certificate has expired. We explicitly persist the
		// key, but log both the certificate and the keyId to the
		// informational logs so an admin can recover the removed cert if
		// necessary or remove the key (and know which cert it belonged to),
		// if desired.
		msg := "[Tidy on mount: %v] Issuer %v has expired by %v and is being removed."
		idAndName := fmt.Sprintf("[id:%v/name:%v]", entry.ID, entry.Name)
		msg = fmt.Sprintf(msg, b.backendUUID, idAndName, config.IssuerSafetyBuffer)

		// Before we log, check if we're the default. While this is late, and
		// after we read it from storage, we have more info here to tell the
		// user that their default has expired AND has passed the safety
		// buffer.
		if iConfig.DefaultIssuerId == issuer {
			msg = "[Tidy on mount: %v] Issuer %v has expired and would be removed via tidy, but won't be, as it is currently the default issuer."
			msg = fmt.Sprintf(msg, b.backendUUID, idAndName)
			b.Logger().Warn(msg)
			continue
		}

		// Log the above message..
		b.Logger().Info(msg, "serial_number", entry.SerialNumber, "key_id", entry.KeyID, "certificate", entry.Certificate)

		wasDefault, err := sc.deleteIssuer(issuer)
		if err != nil {
			b.Logger().Error(fmt.Sprintf("failed to remove %v: %v", idAndName, err))
			return err
		}
		if wasDefault {
			b.Logger().Warn(fmt.Sprintf("expired issuer %v was default; it is strongly encouraged to choose a new default issuer for backwards compatibility", idAndName))
		}

		rebuildChainsAndCRL = true
	}

	if rebuildChainsAndCRL {
		// When issuers are removed, there's a chance chains change as a
		// result; remove them.
		if err := sc.rebuildIssuersChains(nil); err != nil {
			return err
		}

		// Removal of issuers is generally a good reason to rebuild the CRL,
		// even if auto-rebuild is enabled.
		b.revokeStorageLock.Lock()
		defer b.revokeStorageLock.Unlock()

		warnings, err := b.crlBuilder.rebuild(sc, false)
		if err != nil {
			return err
		}
		if len(warnings) > 0 {
			msg := "During rebuild of CRL for tidy, got the following warnings:"
			for index, warning := range warnings {
				msg = fmt.Sprintf("%v\n %d. %v", msg, index+1, warning)
			}
			b.Logger().Warn(msg)
		}
	}

	return nil
}

func (b *backend) doTidyMoveCABundle(ctx context.Context, req *logical.Request, logger hclog.Logger, config *tidyConfig) error {
	// We do not support cancelling within this operation; any cancel will
	// occur before or after this operation.

	if b.System().ReplicationState().HasState(consts.ReplicationDRSecondary|consts.ReplicationPerformanceStandby) ||
		(!b.System().LocalMount() && b.System().ReplicationState().HasState(consts.ReplicationPerformanceSecondary)) {
		b.Logger().Debug("skipping moving the legacy CA bundle as we're not on the primary or secondary with a local mount")
		return nil
	}

	// Short-circuit to avoid moving the legacy bundle from under a legacy
	// mount.
	if b.useLegacyBundleCaStorage() {
		return nil
	}

	// If we've already run, exit.
	_, bundle, err := getLegacyCertBundle(ctx, req.Storage)
	if err != nil {
		return fmt.Errorf("failed to fetch the legacy CA bundle: %w", err)
	}

	if bundle == nil {
		b.Logger().Debug("No legacy CA bundle available; nothing to do.")
		return nil
	}

	log, err := getLegacyBundleMigrationLog(ctx, req.Storage)
	if err != nil {
		return fmt.Errorf("failed to fetch the legacy bundle migration log: %w", err)
	}

	if log == nil {
		return fmt.Errorf("refusing to tidy with an empty legacy migration log but present CA bundle: %w", err)
	}

	if time.Since(log.Created) <= config.IssuerSafetyBuffer {
		b.Logger().Debug("Migration was created too recently to remove the legacy bundle; refusing to move legacy CA bundle to backup location.")
		return nil
	}

	// Do the write before the delete.
	entry, err := logical.StorageEntryJSON(legacyCertBundleBackupPath, bundle)
	if err != nil {
		return fmt.Errorf("failed to create new backup storage entry: %w", err)
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return fmt.Errorf("failed to write new backup legacy CA bundle: %w", err)
	}

	err = req.Storage.Delete(ctx, legacyCertBundlePath)
	if err != nil {
		return fmt.Errorf("failed to remove old legacy CA bundle path: %w", err)
	}

	b.Logger().Info("legacy CA bundle successfully moved to backup location")
	return nil
}

func (b *backend) doTidyAcme(ctx context.Context, req *logical.Request, logger hclog.Logger, config *tidyConfig) error {
	b.acmeAccountLock.Lock()
	defer b.acmeAccountLock.Unlock()

	sc := b.makeStorageContext(ctx, req.Storage)
	var thumbprintsCount uint
	var lenThumbprints int

	itemCallback := func(page int, index int, thumbprint string) (bool, error) {
		b.tidyStatusMessage(fmt.Sprintf("Tidying Acme: checking entry %d of %d on current page; total thumbprints checked: %d", index, lenThumbprints, int(thumbprintsCount)+index))

		err := b.tidyAcmeAccountByThumbprint(b.acmeState, sc, thumbprint, config.SafetyBuffer, config.AcmeAccountSafetyBuffer)
		if err != nil {
			logger.Warn("error tidying account %v: %v", thumbprint, err.Error())
		}

		// Check for cancel before continuing.
		if atomic.CompareAndSwapUint32(b.tidyCancelCAS, 1, 0) {
			return false, tidyCancelledError
		}

		// Check for pause duration to reduce resource consumption.
		if config.PauseDuration > (0 * time.Second) {
			b.acmeAccountLock.Unlock() // Correct the Lock
			time.Sleep(config.PauseDuration)
			b.acmeAccountLock.Lock()
		}
		return true, nil
	}

	// Define batch-level callback that updates cumulative count after processing the page
	batchCallback := func(page int, entries []string) (bool, error) {
		thumbprintsCount += uint(lenThumbprints)
		return true, nil
	}

	// Use HandleListPage to process paginated results
	err := logical.HandleListPage(ctx, req.Storage, acmeThumbprintPrefix, config.PageSize, itemCallback, batchCallback)
	if err != nil {
		return err
	}

	b.tidyStatusLock.Lock()
	b.tidyStatus.acmeAccountsCount = uint(thumbprintsCount)
	b.tidyStatusLock.Unlock()

	// Clean up unused ACME EABs with pagination
	var eabAfter string
	var eabCount uint
	var lenEabIds int
	for {
		eabIds, err := b.acmeState.ListEabIdsPage(sc, eabAfter, config.PageSize)
		if err != nil {
			return fmt.Errorf("failed listing EAB ids: %w", err)
		}

		// If no eabIds are returned, we've reached the end of the list
		if len(eabIds) == 0 {
			break
		}

		lenEabIds = len(eabIds)
		eabAfter = eabIds[lenEabIds-1]

		for i, eabId := range eabIds {
			b.tidyStatusMessage(fmt.Sprintf("Tidying Acme EAB Id's: checking entry %d of %d on current page; total EAB Id's checked: %d", i, lenEabIds, int(eabCount)+i))

			eab, err := b.acmeState.LoadEab(sc, eabId)
			if err != nil {
				if errors.Is(err, ErrStorageItemNotFound) {
					// We don't need to worry about a consumed EAB
					continue
				}
				return err
			}

			eabExpiration := eab.CreatedOn.Add(config.AcmeAccountSafetyBuffer)
			if time.Now().After(eabExpiration) {
				if _, err := b.acmeState.DeleteEab(sc, eabId); err != nil {
					return fmt.Errorf("failed to tidy eab %s: %w", eabId, err)
				}
			}

			// Check for cancel before continuing.
			if atomic.CompareAndSwapUint32(b.tidyCancelCAS, 1, 0) {
				return tidyCancelledError
			}

			// Check for pause duration to reduce resource consumption.
			if config.PauseDuration > 0 {
				b.acmeAccountLock.Unlock() // Correct the Lock
				time.Sleep(config.PauseDuration)
				b.acmeAccountLock.Lock()
			}
		}
		eabCount += uint(lenEabIds)
	}

	return nil
}

func (b *backend) pathTidyCancelWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if atomic.LoadUint32(b.tidyCASGuard) == 0 {
		resp := &logical.Response{}
		resp.AddWarning("Tidy operation cannot be cancelled as none is currently running.")
		return resp, nil
	}

	// Grab the status lock before writing the cancel atomic. This lets us
	// update the status correctly as well, avoiding writing it if we're not
	// presently running.
	//
	// Unlock needs to occur prior to calling read.
	b.tidyStatusLock.Lock()
	if b.tidyStatus.state == tidyStatusStarted || atomic.LoadUint32(b.tidyCASGuard) == 1 {
		if atomic.CompareAndSwapUint32(b.tidyCancelCAS, 0, 1) {
			b.tidyStatus.state = tidyStatusCancelling
		}
	}
	b.tidyStatusLock.Unlock()

	return b.pathTidyStatusRead(ctx, req, d)
}

func (b *backend) pathTidyStatusRead(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.tidyStatusLock.RLock()
	defer b.tidyStatusLock.RUnlock()

	resp := &logical.Response{
		Data: map[string]interface{}{
			"safety_buffer":                         nil,
			"revoked_safety_buffer":                 nil,
			"issuer_safety_buffer":                  nil,
			"tidy_cert_store":                       nil,
			"tidy_revoked_certs":                    nil,
			"tidy_invalid_certs":                    nil,
			"tidy_revoked_cert_issuer_associations": nil,
			"tidy_expired_issuers":                  nil,
			"tidy_move_legacy_ca_bundle":            nil,
			"tidy_acme":                             nil,
			"pause_duration":                        nil,
			"page_size":                             nil,
			"state":                                 "Inactive",
			"error":                                 nil,
			"time_started":                          nil,
			"time_finished":                         nil,
			"message":                               nil,
			"cert_store_deleted_count":              nil,
			"revoked_cert_deleted_count":            nil,
			"missing_issuer_cert_count":             nil,
			"current_cert_store_count":              nil,
			"current_revoked_cert_count":            nil,
			"internal_backend_uuid":                 nil,
			"total_acme_account_count":              nil,
			"acme_account_deleted_count":            nil,
			"acme_account_revoked_count":            nil,
			"acme_orders_deleted_count":             nil,
			"acme_account_safety_buffer":            nil,
		},
	}

	resp.Data["internal_backend_uuid"] = b.backendUUID

	if b.certCountEnabled.Load() {
		resp.Data["current_cert_store_count"] = b.certCount.Load()
		resp.Data["current_revoked_cert_count"] = b.revokedCertCount.Load()
		if !b.certsCounted.Load() {
			resp.AddWarning("Certificates in storage are still being counted, current counts provided may be " +
				"inaccurate")
		}
		if b.certCountError != "" {
			resp.Data["certificate_counting_error"] = b.certCountError
		}
	}

	if b.tidyStatus.state == tidyStatusInactive {
		return resp, nil
	}

	resp.Data["safety_buffer"] = b.tidyStatus.safetyBuffer
	resp.Data["revoked_safety_buffer"] = b.tidyStatus.revokedSafetyBuffer
	resp.Data["issuer_safety_buffer"] = b.tidyStatus.issuerSafetyBuffer
	resp.Data["tidy_cert_store"] = b.tidyStatus.tidyCertStore
	resp.Data["tidy_revoked_certs"] = b.tidyStatus.tidyRevokedCerts
	resp.Data["tidy_invalid_certs"] = b.tidyStatus.tidyInvalidCerts
	resp.Data["tidy_revoked_cert_issuer_associations"] = b.tidyStatus.tidyRevokedAssocs
	resp.Data["tidy_expired_issuers"] = b.tidyStatus.tidyExpiredIssuers
	resp.Data["tidy_move_legacy_ca_bundle"] = b.tidyStatus.tidyBackupBundle
	resp.Data["tidy_acme"] = b.tidyStatus.tidyAcme
	resp.Data["pause_duration"] = b.tidyStatus.pauseDuration
	resp.Data["page_size"] = b.tidyStatus.pageSize
	resp.Data["time_started"] = b.tidyStatus.timeStarted
	resp.Data["message"] = b.tidyStatus.message
	resp.Data["cert_store_deleted_count"] = b.tidyStatus.certStoreDeletedCount
	resp.Data["revoked_cert_deleted_count"] = b.tidyStatus.revokedCertDeletedCount
	resp.Data["missing_issuer_cert_count"] = b.tidyStatus.missingIssuerCertCount
	resp.Data["last_auto_tidy_finished"] = b.lastTidy
	resp.Data["total_acme_account_count"] = b.tidyStatus.acmeAccountsCount
	resp.Data["acme_account_deleted_count"] = b.tidyStatus.acmeAccountsDeletedCount
	resp.Data["acme_account_revoked_count"] = b.tidyStatus.acmeAccountsRevokedCount
	resp.Data["acme_orders_deleted_count"] = b.tidyStatus.acmeOrdersDeletedCount
	resp.Data["acme_account_safety_buffer"] = b.tidyStatus.acmeAccountSafetyBuffer

	switch b.tidyStatus.state {
	case tidyStatusStarted:
		resp.Data["state"] = "Running"
	case tidyStatusFinished:
		resp.Data["state"] = "Finished"
		resp.Data["time_finished"] = b.tidyStatus.timeFinished
		resp.Data["message"] = nil
	case tidyStatusError:
		resp.Data["state"] = "Error"
		resp.Data["time_finished"] = b.tidyStatus.timeFinished
		resp.Data["error"] = b.tidyStatus.err.Error()
		// Don't clear the message so that it serves as a hint about when
		// the error occurred.
	case tidyStatusCancelling:
		resp.Data["state"] = "Cancelling"
	case tidyStatusCancelled:
		resp.Data["state"] = "Cancelled"
		resp.Data["time_finished"] = b.tidyStatus.timeFinished
	}

	return resp, nil
}

func (b *backend) pathConfigAutoTidyRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)
	config, err := sc.getAutoTidyConfig()
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: getTidyConfigData(*config),
	}, nil
}

func (b *backend) pathConfigAutoTidyWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)
	config, err := sc.getAutoTidyConfig()
	if err != nil {
		return nil, err
	}

	if enabledRaw, ok := d.GetOk("enabled"); ok {
		config.Enabled = enabledRaw.(bool)
	}

	if intervalRaw, ok := d.GetOk("interval_duration"); ok {
		config.Interval = time.Duration(intervalRaw.(int)) * time.Second
		if config.Interval < 0 {
			return logical.ErrorResponse("given interval_duration must be greater than or equal to zero seconds; got: %v", intervalRaw), nil
		}
	}

	if certStoreRaw, ok := d.GetOk("tidy_cert_store"); ok {
		config.CertStore = certStoreRaw.(bool)
	}

	if revokedCertsRaw, ok := d.GetOk("tidy_revoked_certs"); ok {
		config.RevokedCerts = revokedCertsRaw.(bool)
	}

	if InvalidCertsRaw, ok := d.GetOk("tidy_invalid_certs"); ok {
		config.InvalidCerts = InvalidCertsRaw.(bool)
	}

	if issuerAssocRaw, ok := d.GetOk("tidy_revoked_cert_issuer_associations"); ok {
		config.IssuerAssocs = issuerAssocRaw.(bool)
	}

	if safetyBufferRaw, ok := d.GetOk("safety_buffer"); ok {
		config.SafetyBuffer = time.Duration(safetyBufferRaw.(int)) * time.Second
		if config.SafetyBuffer < 1*time.Second {
			return logical.ErrorResponse("given safety_buffer must be at least one second; got: %v", safetyBufferRaw), nil
		}
	}

	if revokedSafetyBufferRaw, ok := d.GetOk("revoked_safety_buffer"); ok {
		revokedSafetyBuffer := time.Duration(revokedSafetyBufferRaw.(int)) * time.Second
		config.RevokedSafetyBuffer = &revokedSafetyBuffer
		if *config.RevokedSafetyBuffer < 1*time.Second {
			return logical.ErrorResponse("revoked_safety_buffer must be at least one second; got: %v", revokedSafetyBufferRaw), nil
		}
	}

	if pauseDurationRaw, ok := d.GetOk("pause_duration"); ok {
		config.PauseDuration, err = parseutil.ParseDurationSecond(pauseDurationRaw.(string))
		if err != nil {
			return logical.ErrorResponse("unable to parse given pause_duration: %v", err), nil
		}

		if config.PauseDuration < (0 * time.Second) {
			return logical.ErrorResponse("received invalid, negative pause_duration"), nil
		}
	}

	if PageSizeRaw, ok := d.GetOk("page_size"); ok {
		config.PageSize = PageSizeRaw.(int)
		if config.PageSize < 5 {
			return logical.ErrorResponse("page_size must be at least 5"), nil
		}
	}

	if expiredIssuers, ok := d.GetOk("tidy_expired_issuers"); ok {
		config.ExpiredIssuers = expiredIssuers.(bool)
	}

	if issuerSafetyBufferRaw, ok := d.GetOk("issuer_safety_buffer"); ok {
		config.IssuerSafetyBuffer = time.Duration(issuerSafetyBufferRaw.(int)) * time.Second
		if config.IssuerSafetyBuffer < 1*time.Second {
			return logical.ErrorResponse("given safety_buffer must be at least one second; got: %v", issuerSafetyBufferRaw), nil
		}
	}

	if backupBundle, ok := d.GetOk("tidy_move_legacy_ca_bundle"); ok {
		config.BackupBundle = backupBundle.(bool)
	}

	if tidyAcmeRaw, ok := d.GetOk("tidy_acme"); ok {
		config.TidyAcme = tidyAcmeRaw.(bool)
	}

	if acmeAccountSafetyBufferRaw, ok := d.GetOk("acme_account_safety_buffer"); ok {
		config.AcmeAccountSafetyBuffer = time.Duration(acmeAccountSafetyBufferRaw.(int)) * time.Second
		if config.AcmeAccountSafetyBuffer < 1*time.Second {
			return logical.ErrorResponse("given acme_account_safety_buffer must be at least one second; got: %v", acmeAccountSafetyBufferRaw), nil
		}
	}

	if config.Enabled && !config.IsAnyTidyEnabled() {
		return logical.ErrorResponse("Auto-tidy enabled but no tidy operations were requested. Enable at least one tidy operation to be run (" + config.AnyTidyConfig() + ")."), nil
	}

	if maintainCountEnabledRaw, ok := d.GetOk("maintain_stored_certificate_counts"); ok {
		config.MaintainCount = maintainCountEnabledRaw.(bool)
	}

	if runningStorageMetricsEnabledRaw, ok := d.GetOk("publish_stored_certificate_count_metrics"); ok {
		config.PublishMetrics = runningStorageMetricsEnabledRaw.(bool)
	}

	if config.PublishMetrics && !config.MaintainCount {
		return logical.ErrorResponse("Can not publish a running storage metrics count to metrics without first maintaining that count.  Enable `maintain_stored_certificate_counts` to enable `publish_stored_certificate_count_metrics`."), nil
	}

	if err := sc.writeAutoTidyConfig(config); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: getTidyConfigData(*config),
	}, nil
}

func (b *backend) tidyStatusStart(config *tidyConfig) {
	b.tidyStatusLock.Lock()
	defer b.tidyStatusLock.Unlock()

	revokedSafetyBuffer := int(config.SafetyBuffer / time.Second)
	if config.RevokedSafetyBuffer != nil {
		revokedSafetyBuffer = int(*config.RevokedSafetyBuffer / time.Second)
	}

	b.tidyStatus = &tidyStatus{
		safetyBuffer:            int(config.SafetyBuffer / time.Second),
		revokedSafetyBuffer:     revokedSafetyBuffer,
		issuerSafetyBuffer:      int(config.IssuerSafetyBuffer / time.Second),
		acmeAccountSafetyBuffer: int(config.AcmeAccountSafetyBuffer / time.Second),
		tidyCertStore:           config.CertStore,
		tidyRevokedCerts:        config.RevokedCerts,
		tidyRevokedAssocs:       config.IssuerAssocs,
		tidyExpiredIssuers:      config.ExpiredIssuers,
		tidyBackupBundle:        config.BackupBundle,
		tidyAcme:                config.TidyAcme,
		pauseDuration:           config.PauseDuration.String(),
		pageSize:                config.PageSize,

		state:       tidyStatusStarted,
		timeStarted: time.Now(),
	}

	metrics.SetGauge([]string{"secrets", "pki", "tidy", "start_time_epoch"}, float32(b.tidyStatus.timeStarted.Unix()))
}

func (b *backend) tidyStatusStop(err error) {
	b.tidyStatusLock.Lock()
	defer b.tidyStatusLock.Unlock()

	b.tidyStatus.timeFinished = time.Now()
	b.tidyStatus.err = err
	if err == nil {
		b.tidyStatus.state = tidyStatusFinished
	} else if err == tidyCancelledError {
		b.tidyStatus.state = tidyStatusCancelled
	} else {
		b.tidyStatus.state = tidyStatusError
	}

	metrics.MeasureSince([]string{"secrets", "pki", "tidy", "duration"}, b.tidyStatus.timeStarted)
	metrics.SetGauge([]string{"secrets", "pki", "tidy", "start_time_epoch"}, 0)
	metrics.IncrCounter([]string{"secrets", "pki", "tidy", "cert_store_deleted_count"}, float32(b.tidyStatus.certStoreDeletedCount))
	metrics.IncrCounter([]string{"secrets", "pki", "tidy", "revoked_cert_deleted_count"}, float32(b.tidyStatus.revokedCertDeletedCount))

	if err != nil {
		metrics.IncrCounter([]string{"secrets", "pki", "tidy", "failure"}, 1)
	} else {
		metrics.IncrCounter([]string{"secrets", "pki", "tidy", "success"}, 1)
	}
}

func (b *backend) tidyStatusMessage(msg string) {
	b.tidyStatusLock.Lock()
	defer b.tidyStatusLock.Unlock()

	b.tidyStatus.message = msg
}

func (b *backend) tidyStatusIncCertStoreCount() {
	b.tidyStatusLock.Lock()
	defer b.tidyStatusLock.Unlock()

	b.tidyStatus.certStoreDeletedCount++

	b.ifCountEnabledDecrementTotalCertificatesCountReport()
}

func (b *backend) tidyStatusIncRevokedCertCount() {
	b.tidyStatusLock.Lock()
	defer b.tidyStatusLock.Unlock()

	b.tidyStatus.revokedCertDeletedCount++

	b.ifCountEnabledDecrementTotalRevokedCertificatesCountReport()
}

func (b *backend) tidyStatusIncMissingIssuerCertCount() {
	b.tidyStatusLock.Lock()
	defer b.tidyStatusLock.Unlock()

	b.tidyStatus.missingIssuerCertCount++
}

func (b *backend) tidyStatusIncRevAcmeAccountCount() {
	b.tidyStatusLock.Lock()
	defer b.tidyStatusLock.Unlock()

	b.tidyStatus.acmeAccountsRevokedCount++
}

func (b *backend) tidyStatusIncDeletedAcmeAccountCount() {
	b.tidyStatusLock.Lock()
	defer b.tidyStatusLock.Unlock()

	b.tidyStatus.acmeAccountsDeletedCount++
}

func (b *backend) tidyStatusIncDelAcmeOrderCount() {
	b.tidyStatusLock.Lock()
	defer b.tidyStatusLock.Unlock()

	b.tidyStatus.acmeOrdersDeletedCount++
}

const pathTidyHelpSyn = `
Tidy up the backend by removing expired certificates, revocation information,
or both.
`

const pathTidyHelpDesc = `
This endpoint allows expired certificates and/or revocation information to be
removed from the backend, freeing up storage and shortening CRLs.

For safety, this function is a noop if called without parameters; cleanup from
normal certificate storage must be enabled with 'tidy_cert_store' and cleanup
from revocation information must be enabled with 'tidy_revocation_list'.

The 'safety_buffer' parameter is useful to ensure that clock skew amongst your
hosts cannot lead to an expired certificate being removed from certificate storage 
while it is still considered valid by other hosts (for instance, if their clocks 
are a few minutes behind). The 'safety_buffer' parameter can be an integer number 
of seconds or a string duration like "72h".

The 'revoked_safety_buffer' parameter can be used to ensure that clock skew amongst 
your hosts cannot lead to a revoked certificate being removed from the CRL while it 
is still considered valid by other hosts (for instance, if their clocks are a few 
minutes behind). The 'revoked_safety_buffer' defaults 'safety_buffer' if it is unset
and can be an integer number of seconds or a string duration like "72h".

All certificates and/or revocation information currently stored in the backend
will be checked when this endpoint is hit. The expiration of the
certificate/revocation information of each certificate being held in
certificate storage or in revocation information will then be checked. If the
current time, minus the value of 'safety_buffer', is greater than the
expiration, it will be removed. If the current time, minus the value of 
'revoked_safety_buffer', is greater than the revoked time, it will be removed.
`

const pathTidyCancelHelpSyn = `
Cancels a currently running tidy operation.
`

const pathTidyCancelHelpDesc = `
This endpoint allows cancelling a currently running tidy operation.

Periodically throughout the invocation of tidy, we'll check if the operation
has been requested to be cancelled. If so, we'll stop the currently running
tidy operation.
`

const pathTidyStatusHelpSyn = `
Returns the status of the tidy operation.
`

const pathTidyStatusHelpDesc = `
This is a read only endpoint that returns information about the current tidy
operation, or the most recent if none is currently running.

The result includes the following fields:
* 'safety_buffer': the value of this parameter when initiating the tidy operation
* 'revoked_safety_buffer': the value of this parameter when initiating the tidy operation
* 'tidy_cert_store': the value of this parameter when initiating the tidy operation
* 'tidy_revoked_certs': the value of this parameter when initiating the tidy operation
* 'tidy_invalid_certs': the value of this parameter when initiating the tidy operation
* 'tidy_revoked_cert_issuer_associations': the value of this parameter when initiating the tidy operation
* 'state': one of "Inactive", "Running", "Finished", "Error"
* 'error': the error message, if the operation ran into an error
* 'time_started': the time the operation started
* 'time_finished': the time the operation finished
* 'message': One of "Tidying certificate store: checking entry N of TOTAL" or
  "Tidying revoked certificates: checking certificate N of TOTAL"
* 'cert_store_deleted_count': The number of certificate storage entries deleted
* 'revoked_cert_deleted_count': The number of revoked certificate entries deleted
* 'missing_issuer_cert_count': The number of revoked certificates which were missing a valid issuer reference
* 'tidy_expired_issuers': the value of this parameter when initiating the tidy operation
* 'issuer_safety_buffer': the value of this parameter when initiating the tidy operation
* 'tidy_move_legacy_ca_bundle': the value of this parameter when initiating the tidy operation
* 'tidy_acme': the value of this parameter when initiating the tidy operation
* 'acme_account_safety_buffer': the value of this parameter when initiating the tidy operation
* 'pause_duration: the value of this parameter when initiating the tidy operation
* 'page_size': the value of this parameter when initiating the tidy operation
* 'total_acme_account_count': the total number of acme accounts in the list to be iterated over
* 'acme_account_deleted_count': the number of revoked acme accounts deleted during the operation
* 'acme_account_revoked_count': the number of acme accounts revoked during the operation
* 'acme_orders_deleted_count': the number of acme orders deleted during the operation
`

const pathConfigAutoTidySyn = `
Modifies the current configuration for automatic tidy execution.
`

const pathConfigAutoTidyDesc = `
This endpoint accepts parameters to a tidy operation (see /tidy) that
will be used for automatic tidy execution. This takes two extra parameters,
enabled (to enable or disable auto-tidy) and interval_duration (which
controls the frequency of auto-tidy execution).

Once enabled, a tidy operation will be kicked off automatically, as if it
were executed with the posted configuration.
`

func getTidyConfigData(config tidyConfig) map[string]interface{} {
	revokedSafetyBufferValue := int(config.SafetyBuffer / time.Second)
	if config.RevokedSafetyBuffer != nil {
		revokedSafetyBufferValue = int(*config.RevokedSafetyBuffer / time.Second)
	}
	return map[string]interface{}{
		// This map is in the same order as tidyConfig to ensure that all fields are accounted for
		"enabled":                                  config.Enabled,
		"interval_duration":                        int(config.Interval / time.Second),
		"tidy_cert_store":                          config.CertStore,
		"tidy_revoked_certs":                       config.RevokedCerts,
		"tidy_invalid_certs":                       config.InvalidCerts,
		"tidy_revoked_cert_issuer_associations":    config.IssuerAssocs,
		"tidy_expired_issuers":                     config.ExpiredIssuers,
		"tidy_move_legacy_ca_bundle":               config.BackupBundle,
		"tidy_acme":                                config.TidyAcme,
		"safety_buffer":                            int(config.SafetyBuffer / time.Second),
		"revoked_safety_buffer":                    revokedSafetyBufferValue,
		"issuer_safety_buffer":                     int(config.IssuerSafetyBuffer / time.Second),
		"acme_account_safety_buffer":               int(config.AcmeAccountSafetyBuffer / time.Second),
		"pause_duration":                           config.PauseDuration.String(),
		"page_size":                                config.PageSize,
		"publish_stored_certificate_count_metrics": config.PublishMetrics,
		"maintain_stored_certificate_counts":       config.MaintainCount,
	}
}
