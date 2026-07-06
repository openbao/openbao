// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	remotedb "github.com/openbao/openbao/plugins/database/remote-db-plugin"
	"github.com/openbao/openbao/plugins/database/remote-db-plugin/bootstrap"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// --- ca/init -----------------------------------------------------------------

func (b *relayBackend) pathCAInit() *framework.Path {
	return &framework.Path{
		Pattern: "ca/init",
		Fields: map[string]*framework.FieldSchema{
			"hub_endpoint": {
				Type:        framework.TypeString,
				Description: "host:port the proxy gRPC listener will advertise to spokes.",
			},
			"hub_dns_sans": {
				Type:        framework.TypeCommaStringSlice,
				Description: "DNS names to include as SANs on the hub TLS cert. Comma-separated or repeated.",
			},
			"hub_ip_sans": {
				Type:        framework.TypeCommaStringSlice,
				Description: "IPs to include as SANs on the hub TLS cert. Comma-separated or repeated.",
			},
			"force": {
				Type:        framework.TypeBool,
				Description: "If true, regenerate the CA even if one already exists.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleCAInit},
		},
		HelpSynopsis: "Initialize the spoke certificate authority and hub TLS identity.",
	}
}

func (b *relayBackend) handleCAInit(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	endpoint := d.Get("hub_endpoint").(string)
	if endpoint == "" {
		return logical.ErrorResponse("hub_endpoint is required"), nil
	}
	port, err := portFromEndpoint(endpoint)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf(
			"hub_endpoint must be host:port (%v)", err,
		)), nil
	}
	dnsSANs := d.Get("hub_dns_sans").([]string)
	ipSANs := d.Get("hub_ip_sans").([]string)
	force := d.Get("force").(bool)

	// Serialize against other CA-mutating paths (ca/init, ca/rotate,
	// ca/update-endpoint) so the read-check-write block sees a stable view
	// of storage. Without this, two concurrent ca/init calls both pass the
	// existing==nil check and both write a CA — the second overwrites the
	// first, orphaning any spoke that already fetched the first via
	// cluster-info.
	b.caMu.Lock()
	defer b.caMu.Unlock()

	existing, err := readCA(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if existing != nil && !force {
		return logical.ErrorResponse(bootstrap.MsgCAAlreadyInitialized + "; pass force=true to regenerate"), nil
	}

	ca, err := bootstrap.GenerateCA()
	if err != nil {
		return nil, err
	}
	hub, err := ca.IssueHubServerCert(dnsSANs, ipSANs)
	if err != nil {
		return nil, err
	}

	bundle := &caStorage{
		CACertPEM:   ca.CertPEM,
		CAKeyPEM:    ca.KeyPEM,
		HubCertPEM:  hub.CertPEM,
		HubKeyPEM:   hub.KeyPEM,
		HubEndpoint: endpoint,
		CreatedUnix: time.Now().Unix(),
	}
	if err := writeCA(ctx, req.Storage, bundle); err != nil {
		return nil, err
	}
	if err := bootstrap.Global().SetIdentity(ca, hub); err != nil {
		return nil, err
	}
	// Bring up the gRPC listener now, while we have an authenticated operator
	// holding the response. Doing it here (instead of lazily from the database
	// mount's Initialize) means port problems surface to whoever ran
	// `bao relay init`, not to whoever later mounts a database engine, and the
	// port comes from a single source of truth instead of the first DB mount's
	// relay_port config.
	if err := remotedb.StartProxyServer(port); err != nil {
		return logical.ErrorResponse(fmt.Sprintf("start proxy listener: %v", err)), nil
	}

	caCert, err := bootstrap.ParseCert(ca.CertPEM)
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]any{
			"ca_cert_pem":  string(ca.CertPEM),
			"ca_cert_hash": bootstrap.HashCert(caCert),
			"hub_endpoint": endpoint,
		},
	}, nil
}

// --- ca/info -----------------------------------------------------------------

func (b *relayBackend) pathCAInfo() *framework.Path {
	return &framework.Path{
		Pattern: "ca/info",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.handleCAInfo},
		},
		HelpSynopsis: "Return CA + hub cert metadata.",
	}
}

func (b *relayBackend) handleCAInfo(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	bundle, err := readCA(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if bundle == nil {
		return logical.ErrorResponse("CA not initialized; run `bao relay init`"), nil
	}
	caCert, err := bootstrap.ParseCert(bundle.CACertPEM)
	if err != nil {
		return nil, err
	}
	hubCert, err := bootstrap.ParseCert(bundle.HubCertPEM)
	if err != nil {
		return nil, err
	}

	ipSANs := make([]string, 0, len(hubCert.IPAddresses))
	for _, ip := range hubCert.IPAddresses {
		ipSANs = append(ipSANs, ip.String())
	}

	return &logical.Response{
		Data: map[string]any{
			"ca_cert_pem":        string(bundle.CACertPEM),
			"ca_cert_hash":       bootstrap.HashCert(caCert),
			"ca_subject":         caCert.Subject.String(),
			"ca_not_after":       caCert.NotAfter.Unix(),
			"hub_endpoint":       bundle.HubEndpoint,
			"hub_cert_subject":   hubCert.Subject.String(),
			"hub_cert_not_after": hubCert.NotAfter.Unix(),
			"hub_dns_sans":       hubCert.DNSNames,
			"hub_ip_sans":        ipSANs,
			"created_unix":       bundle.CreatedUnix,
			"listener_port":      remotedb.ProxyServerPort(),
		},
	}, nil
}

// --- ca/update-endpoint ------------------------------------------------------

func (b *relayBackend) pathCAUpdateEndpoint() *framework.Path {
	return &framework.Path{
		Pattern: "ca/update-endpoint",
		Fields: map[string]*framework.FieldSchema{
			"hub_endpoint": {
				Type:        framework.TypeString,
				Description: "New host:port advertised to spokes. Port must match the listening port.",
			},
			"hub_dns_sans": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Replace DNS SANs on the hub TLS cert. Comma-separated or repeated.",
			},
			"hub_ip_sans": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Replace IP SANs on the hub TLS cert. Comma-separated or repeated.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleCAUpdateEndpoint},
		},
		HelpSynopsis: "Change the advertised hub endpoint and/or hub TLS SANs without rotating the CA.",
	}
}

// handleCAUpdateEndpoint lets operators move the advertised hub endpoint (e.g.
// a load-balancer DNS name change) and refresh the hub TLS cert's SANs without
// touching the CA. The CA stays valid, every spoke's ca.pem stays valid, and
// every spoke's client cert stays valid — only the hub's own server cert is
// re-issued. The bound port cannot change here; that requires a process
// restart, so we reject endpoint values whose port differs from the running
// listener's.
func (b *relayBackend) handleCAUpdateEndpoint(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.caMu.Lock()
	defer b.caMu.Unlock()

	bundle, err := readCA(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if bundle == nil {
		return logical.ErrorResponse("CA not initialized; run `bao relay init`"), nil
	}

	newEndpoint := d.Get("hub_endpoint").(string)
	if newEndpoint != "" {
		newPort, err := portFromEndpoint(newEndpoint)
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf(
				"hub_endpoint must be host:port (%v)", err,
			)), nil
		}
		runningPort := remotedb.ProxyServerPort()
		if runningPort != 0 && runningPort != newPort {
			return logical.ErrorResponse(fmt.Sprintf(
				"hub_endpoint port %d does not match the running listener on :%d; "+
					"changing the listen port requires a process restart",
				newPort, runningPort,
			)), nil
		}
		bundle.HubEndpoint = newEndpoint
	}

	dnsSANs := d.Get("hub_dns_sans").([]string)
	ipSANs := d.Get("hub_ip_sans").([]string)

	// Re-issue the hub TLS cert on the existing CA. Carry forward the
	// existing SANs when the operator did not specify replacements, so a
	// caller that only changes the endpoint does not silently drop SANs.
	existingHub, err := bootstrap.ParseCert(bundle.HubCertPEM)
	if err != nil {
		return nil, err
	}
	if len(dnsSANs) == 0 {
		dnsSANs = existingHub.DNSNames
	}
	if len(ipSANs) == 0 {
		ipSANs = make([]string, 0, len(existingHub.IPAddresses))
		for _, ip := range existingHub.IPAddresses {
			ipSANs = append(ipSANs, ip.String())
		}
	}

	ca := &bootstrap.CABundle{CertPEM: bundle.CACertPEM, KeyPEM: bundle.CAKeyPEM}
	newHub, err := ca.IssueHubServerCert(dnsSANs, ipSANs)
	if err != nil {
		return nil, err
	}

	bundle.HubCertPEM = newHub.CertPEM
	bundle.HubKeyPEM = newHub.KeyPEM
	if err := writeCA(ctx, req.Storage, bundle); err != nil {
		return nil, err
	}
	if err := bootstrap.Global().SetIdentity(ca, newHub); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]any{
			"hub_endpoint": bundle.HubEndpoint,
			"hub_dns_sans": dnsSANs,
			"hub_ip_sans":  ipSANs,
		},
	}, nil
}

// --- ca/rotate ---------------------------------------------------------------

func (b *relayBackend) pathCARotate() *framework.Path {
	return &framework.Path{
		Pattern: "ca/rotate",
		Fields: map[string]*framework.FieldSchema{
			"full": {
				Type:        framework.TypeBool,
				Description: "If true, rotate the spoke-CA itself (invalidates all spoke certs).",
			},
			"hub_dns_sans": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Override DNS SANs on the new hub cert; defaults to existing. Comma-separated or repeated.",
			},
			"hub_ip_sans": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Override IP SANs on the new hub cert; defaults to existing. Comma-separated or repeated.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleCARotate},
		},
		HelpSynopsis: "Rotate the hub TLS cert (default) or the entire spoke-CA.",
	}
}

func (b *relayBackend) handleCARotate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.caMu.Lock()
	defer b.caMu.Unlock()

	bundle, err := readCA(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if bundle == nil {
		return logical.ErrorResponse("CA not initialized; run `bao relay init`"), nil
	}

	full := d.Get("full").(bool)
	dnsSANs := d.Get("hub_dns_sans").([]string)
	ipSANs := d.Get("hub_ip_sans").([]string)

	// Carry forward whatever was on the existing hub cert if the operator
	// didn't override. Rotation should not silently drop SANs.
	existingHubCert, err := bootstrap.ParseCert(bundle.HubCertPEM)
	if err != nil {
		return nil, err
	}
	if len(dnsSANs) == 0 {
		dnsSANs = existingHubCert.DNSNames
	}
	if len(ipSANs) == 0 {
		ipSANs = make([]string, 0, len(existingHubCert.IPAddresses))
		for _, ip := range existingHubCert.IPAddresses {
			ipSANs = append(ipSANs, ip.String())
		}
	}

	var (
		newCA       *bootstrap.CABundle
		newHub      *bootstrap.HubServerCert
		rotatedKind string
	)
	if full {
		newCA, err = bootstrap.GenerateCA()
		if err != nil {
			return nil, err
		}
		rotatedKind = "ca+hub"
	} else {
		newCA = &bootstrap.CABundle{CertPEM: bundle.CACertPEM, KeyPEM: bundle.CAKeyPEM}
		rotatedKind = "hub"
	}
	newHub, err = newCA.IssueHubServerCert(dnsSANs, ipSANs)
	if err != nil {
		return nil, err
	}

	updated := &caStorage{
		CACertPEM:   newCA.CertPEM,
		CAKeyPEM:    newCA.KeyPEM,
		HubCertPEM:  newHub.CertPEM,
		HubKeyPEM:   newHub.KeyPEM,
		HubEndpoint: bundle.HubEndpoint, // endpoint never changes via rotate
		CreatedUnix: bundle.CreatedUnix,
	}
	if err := writeCA(ctx, req.Storage, updated); err != nil {
		return nil, err
	}
	if err := bootstrap.Global().SetIdentity(newCA, newHub); err != nil {
		return nil, err
	}

	caCert, err := bootstrap.ParseCert(newCA.CertPEM)
	if err != nil {
		return nil, err
	}
	resp := &logical.Response{
		Data: map[string]any{
			"rotated":      rotatedKind,
			"ca_cert_hash": bootstrap.HashCert(caCert),
			"ca_cert_pem":  string(newCA.CertPEM),
		},
	}
	if full {
		resp.AddWarning(strings.Join([]string{
			"Full CA rotation invalidates every issued spoke cert AND every spoke's local ca.pem.",
			"Active gRPC streams stay up until they disconnect (TLS auth happens at handshake), but:",
			"  - the hub no longer trusts existing spoke client certs (new ClientCAs pool),",
			"  - spokes no longer trust the hub server cert (the ca.pem they pinned is for the old CA),",
			"so any reconnect — process restart, network blip, hub restart — will fail in both directions.",
			"Recovery requires, on each spoke: distribute the new ca.pem out of band, create a fresh bootstrap",
			"token (`bao relay token create`), run `bao relay join` to obtain a new client cert + ca.pem,",
			"then restart `bao relay run`. There is no in-band channel that survives a full rotation.",
		}, " "))
	}
	return resp, nil
}

// --- bootstrap-tokens (create + list) ----------------------------------------

func (b *relayBackend) pathTokensCreate() *framework.Path {
	return &framework.Path{
		Pattern: "bootstrap-tokens/?$",
		Fields: map[string]*framework.FieldSchema{
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Token lifetime; defaults to 24h. 0 = never expires.",
			},
			"allowed_spoke_name": {
				Type:        framework.TypeString,
				Description: "If set, the issued spoke cert's CN must equal this value.",
			},
			"description": {
				Type:        framework.TypeString,
				Description: "Free-form description shown in `bao relay token list`.",
			},
			"usages": {
				Type:        framework.TypeStringSlice,
				Description: "Allowed usages; defaults to [signing, authentication].",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleTokenCreate},
			logical.ListOperation:   &framework.PathOperation{Callback: b.handleTokenList},
		},
		HelpSynopsis: "Create or list bootstrap tokens.",
	}
}

func (b *relayBackend) handleTokenCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	ttl := time.Duration(d.Get("ttl").(int)) * time.Second
	if ttl == 0 {
		ttl = defaultTokenTTL
	}
	allowedName := d.Get("allowed_spoke_name").(string)
	description := d.Get("description").(string)
	usages := d.Get("usages").([]string)
	if len(usages) == 0 {
		usages = []string{usageSigning, usageAuthentication}
	}

	tok, err := bootstrap.GenerateToken()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	// Resolve ExpirationUnix once: a negative ttl means "never expires", any
	// non-negative ttl is offset from now. Computing now.Add(ttl) and then
	// overwriting was both confusing and broken for negative inputs — Add
	// produced a past timestamp that the caller saw before the override.
	var expirationUnix int64
	if ttl > 0 {
		expirationUnix = now.Add(ttl).Unix()
	}
	rec := &tokenStorage{
		ID:               tok.ID,
		Secret:           tok.Secret,
		ExpirationUnix:   expirationUnix,
		AllowedSpokeName: allowedName,
		Description:      description,
		Usages:           usages,
		CreatedUnix:      now.Unix(),
	}
	if err := writeToken(ctx, req.Storage, rec); err != nil {
		return nil, err
	}
	resp := &logical.Response{
		Data: map[string]any{
			"id":                 tok.ID,
			"token":              tok.String(),
			"expiration_unix":    rec.ExpirationUnix,
			"allowed_spoke_name": allowedName,
			"usages":             usages,
		},
	}
	// The token is the JWS-HMAC key and the spoke-CSR-signing capability all
	// in one short string. Operators need to see it once — same trade-off as
	// `kubeadm token create` — but they should not see it again in audit
	// logs or forwarded responses. Emit a warning so it shows up next to the
	// token wherever the caller surfaces it.
	resp.AddWarning("This token is shown only once. Communicate it out of band; do not store or log it. Configure audit_non_hmac_response_keys=token on the relay mount and request response wrapping (-wrap-ttl) for production use.")
	return resp, nil
}

func (b *relayBackend) handleTokenList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	ids, err := req.Storage.List(ctx, relayStorageTokenPrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(ids), nil
}

// --- bootstrap-tokens/<id> ---------------------------------------------------

func (b *relayBackend) pathTokenItem() *framework.Path {
	return &framework.Path{
		Pattern: "bootstrap-tokens/" + framework.GenericNameRegex("id"),
		Fields: map[string]*framework.FieldSchema{
			"id": {Type: framework.TypeString, Description: "Token id (6 chars)."},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.handleTokenRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.handleTokenDelete},
		},
	}
}

func (b *relayBackend) handleTokenRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	id := d.Get("id").(string)
	t, err := readToken(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]any{
			"id":                 t.ID,
			"expiration_unix":    t.ExpirationUnix,
			"created_unix":       t.CreatedUnix,
			"allowed_spoke_name": t.AllowedSpokeName,
			"description":        t.Description,
			"usages":             t.Usages,
			"expired":            t.expired(),
		},
	}, nil
}

func (b *relayBackend) handleTokenDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	id := d.Get("id").(string)
	if err := req.Storage.Delete(ctx, relayStorageTokenPrefix+id); err != nil {
		return nil, err
	}
	return nil, nil
}

// --- cluster-info (UNAUTH) ---------------------------------------------------

func (b *relayBackend) pathClusterInfo() *framework.Path {
	return &framework.Path{
		Pattern: "cluster-info",
		Fields: map[string]*framework.FieldSchema{
			"token_id": {
				Type:        framework.TypeString,
				Description: "Bootstrap token id; required for the JWS signature.",
				Query:       true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.handleClusterInfo},
		},
		HelpSynopsis: "Public hub-info bundle, signed with the bootstrap token's secret.",
	}
}

// clusterInfoPayload is what the spoke verifies against the JWS. It must be
// re-marshaled in a deterministic order on both sides; since both sides use
// encoding/json with the same struct, the order is stable.
type clusterInfoPayload struct {
	CACertPEM   string `json:"ca_cert_pem"`
	HubEndpoint string `json:"hub_endpoint"`
}

func (b *relayBackend) handleClusterInfo(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tokenID := d.Get("token_id").(string)
	if !bootstrap.ValidTokenID(tokenID) {
		// Reject syntactically-bad ids before the storage lookup. The path is
		// unauthenticated and the id space is small (~16M); cheap upfront
		// rejection keeps storage off the hot path for brute-force probes.
		// Pair this with a sys/quotas/rate-limit policy on relay/cluster-info
		// (see DESIGN.md "Hardening").
		return logical.ErrorResponse("token unknown or expired"), nil
	}
	t, err := readToken(ctx, req.Storage, tokenID)
	if err != nil {
		return nil, err
	}
	if t == nil || t.expired() {
		// Returning the same error for both unknown and expired stops a remote
		// caller from enumerating valid ids by timing the response.
		return logical.ErrorResponse("token unknown or expired"), nil
	}
	bundle, err := readCA(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if bundle == nil {
		// Collapsing to the same error as token-not-found avoids leaking
		// whether the hub itself has been initialized via this endpoint.
		// Logged at Info so operators who actually hit this misconfig
		// (a token in storage with no CA — should not happen via the
		// CLI but possible via direct API misuse) can find it without
		// adding scanner noise to WARN-level alerts.
		b.Logger().Info("relay/cluster-info called with a valid token but no CA bundle in storage; returning generic error to caller",
			"token_id", tokenID)
		return logical.ErrorResponse("token unknown or expired"), nil
	}

	payload := clusterInfoPayload{
		CACertPEM:   string(bundle.CACertPEM),
		HubEndpoint: bundle.HubEndpoint,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	sig, err := bootstrap.SignDetached(bootstrap.Token{ID: t.ID, Secret: t.Secret}, payloadBytes)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]any{
			"payload":   string(payloadBytes),
			"signature": sig,
		},
	}, nil
}

// --- sign-csr (UNAUTH, token-authenticated) ----------------------------------

func (b *relayBackend) pathSignCSR() *framework.Path {
	return &framework.Path{
		Pattern: "sign-csr",
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "Bootstrap token in <id>.<secret> form.",
			},
			"spoke_name": {
				Type:        framework.TypeString,
				Description: "Identity the spoke is requesting; becomes the cert CN.",
			},
			"csr_pem": {
				Type:        framework.TypeString,
				Description: "PEM-encoded PKCS#10 CSR.",
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Requested cert validity; capped at 30d if missing.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleSignCSR},
		},
		HelpSynopsis: "Exchange a bootstrap token for a signed spoke client cert.",
	}
}

// genericTokenAuthError is what the unauthenticated relay/sign-csr endpoint
// returns for every failure mode that depends on the token itself: malformed
// format, unknown id, expired, wrong secret, missing usage, wrong
// allowed_spoke_name. A single message keeps an attacker (or even a holder
// of one valid token probing for others' metadata) from distinguishing
// "wrong secret" from "wrong usage" from "wrong spoke restriction" — the
// last two would otherwise leak per-token policy across the token space.
//
// handleSignCSR additionally evaluates every per-token check against a
// placeholder when the id is unknown, so "unknown id" pays the same HMAC +
// per-field work as "known id, wrong secret". The storage read itself can
// still differ slightly between hit and miss depending on the backend; pair
// with a sys/quotas/rate-limit policy on relay/sign-csr to make brute-force
// timing impractical even against a backend with a measurable miss/hit gap.
//
// The real reason is logged server-side so operators can still diagnose.
const genericTokenAuthError = "token unknown or expired"

func (b *relayBackend) handleSignCSR(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	rawTok := d.Get("token").(string)
	spokeName := d.Get("spoke_name").(string)
	csrPEM := d.Get("csr_pem").(string)
	// Clamp BEFORE multiplying by time.Second. time.Duration(seconds) *
	// time.Second overflows int64 around seconds ≈ 9.2e9 and silently
	// produces a negative duration that then falls through to the
	// "ttl <= 0 → default" branch — a 100-year request would become a
	// 30-day cert with no error to the caller. Same overflow trap the
	// proxy.RenewCert RPC already avoids; mirror the pattern so the
	// initial-issue and renew paths agree on behavior at the edges.
	rawTTLSeconds := d.Get("ttl").(int)
	const maxSpokeCertExpirySeconds = int(maxSpokeCertExpiry / time.Second)
	var ttl time.Duration
	switch {
	case rawTTLSeconds <= 0:
		ttl = defaultSpokeCertExpiry
	case rawTTLSeconds >= maxSpokeCertExpirySeconds:
		ttl = maxSpokeCertExpiry
	default:
		ttl = time.Duration(rawTTLSeconds) * time.Second
	}
	if spokeName == "" || csrPEM == "" || rawTok == "" {
		return logical.ErrorResponse("token, spoke_name, csr_pem are all required"), nil
	}

	parsedTok, err := bootstrap.ParseToken(rawTok)
	if err != nil {
		b.Logger().Warn("relay/sign-csr: malformed token", "err", err)
		return logical.ErrorResponse(genericTokenAuthError), nil
	}

	t, err := readToken(ctx, req.Storage, parsedTok.ID)
	if err != nil {
		return nil, err
	}
	// Always run every per-token check below against a non-nil record so
	// "unknown token id" takes the same code path as "known id, wrong
	// secret/usage/spoke". Without this, a single early-return on
	// t == nil leaks via timing: a remote caller with one valid token
	// could distinguish "another id you don't know" from any other
	// failure mode and grind the 16M id space for live ids. The check
	// values themselves go nowhere if the token didn't exist (the
	// secret can never match the zero-byte placeholder), but the work
	// of evaluating them is paid in both branches.
	exists := t != nil
	checkTok := t
	if checkTok == nil {
		checkTok = &tokenStorage{}
	}
	secretEq := bootstrap.ConstantTimeEqualSecret(checkTok.Secret, parsedTok.Secret)
	notExpired := !checkTok.expired()
	usageOK := checkTok.hasUsage(usageSigning)
	spokeOK := checkTok.AllowedSpokeName == "" || checkTok.AllowedSpokeName == spokeName

	// Combine the per-field checks via a named ok before negating so the
	// positive "all required signals" form stays readable. Inlining
	// !(A && B && ...) trips staticcheck QF1001 (De Morgan rewrite); the
	// rewritten || form reads worse in security-sensitive code.
	ok := exists && secretEq && notExpired && usageOK && spokeOK
	if !ok {
		b.Logger().Warn("relay/sign-csr: token auth failed",
			"token_id", parsedTok.ID,
			"exists", exists,
			"secret_eq", secretEq,
			"not_expired", notExpired,
			"usage_ok", usageOK,
			"spoke_ok", spokeOK,
			"requested_spoke_name", spokeName)
		return logical.ErrorResponse(genericTokenAuthError), nil
	}

	bundle, err := readCA(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if bundle == nil {
		return logical.ErrorResponse("hub not initialized"), nil
	}
	ca := &bootstrap.CABundle{CertPEM: bundle.CACertPEM, KeyPEM: bundle.CAKeyPEM}

	csrDER, err := bootstrap.DecodeCSRPEM([]byte(csrPEM))
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	certPEM, err := ca.SignSpokeCSR(csrDER, spokeName, ttl)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	return &logical.Response{
		Data: map[string]any{
			"cert_pem":    string(certPEM),
			"ca_cert_pem": string(bundle.CACertPEM),
		},
	}, nil
}

// --- spokes -----------------------------------------------------------------

func (b *relayBackend) pathSpokes() *framework.Path {
	return &framework.Path{
		Pattern: "spokes",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.handleSpokesList},
			logical.ListOperation: &framework.PathOperation{Callback: b.handleSpokesList},
		},
		HelpSynopsis: "List spokes currently connected to the proxy gRPC server.",
	}
}

func (b *relayBackend) handleSpokesList(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	statuses := remotedb.ListConnectedSpokes()
	now := time.Now()
	entries := make([]map[string]any, 0, len(statuses))
	healthyCount := 0
	for _, s := range statuses {
		if s.Healthy {
			healthyCount++
		}
		entry := map[string]any{
			"name":              s.Name,
			"connected_at_unix": s.ConnectedAt.Unix(),
			"last_seen_unix":    s.LastSeen.Unix(),
			"last_seen_seconds": int64(now.Sub(s.LastSeen) / time.Second),
			"healthy":           s.Healthy,
		}
		// Per-spoke mTLS client-cert expiry (Unix seconds), like ca_not_after.
		// Zero when the hub never captured a verified peer cert.
		if !s.CertNotAfter.IsZero() {
			entry["cert_not_after"] = s.CertNotAfter.Unix()
		} else {
			entry["cert_not_after"] = int64(0)
		}
		entries = append(entries, entry)
	}
	return &logical.Response{
		Data: map[string]any{
			"spokes":              entries,
			"connected_count":     len(statuses),
			"healthy_count":       healthyCount,
			"listener_port":       remotedb.ProxyServerPort(),
			"stale_after_seconds": int64(remotedb.SpokeStaleAfter / time.Second),
		},
	}, nil
}
