// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dependency

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
)

func init() {
	VaultDefaultLeaseDuration = 0
	VaultLeaseRenewalThreshold = .90
}

func TestVaultRenewDuration(t *testing.T) {
	renewable := Secret{LeaseDuration: 100, Renewable: true}
	renewableDur := leaseCheckWait(&renewable).Seconds()
	if renewableDur < 16 || renewableDur >= 34 {
		t.Fatalf("renewable duration is not within 1/6 to 1/3 of lease duration: %f", renewableDur)
	}

	nonRenewable := Secret{LeaseDuration: 100}
	nonRenewableDur := leaseCheckWait(&nonRenewable).Seconds()
	if nonRenewableDur < 80 || nonRenewableDur > 95 {
		t.Fatalf("renewable duration is not within 80%% to 95%% of lease duration: %f", nonRenewableDur)
	}

	data := map[string]interface{}{
		"rotation_period": json.Number("60"),
		"ttl":             json.Number("30"),
	}

	nonRenewableRotated := Secret{LeaseDuration: 100, Data: data}
	nonRenewableRotatedDur := leaseCheckWait(&nonRenewableRotated).Seconds()

	// We expect a 1 second cushion
	if nonRenewableRotatedDur != 31 {
		t.Fatalf("renewable duration is not 31: %f", nonRenewableRotatedDur)
	}

	data = map[string]interface{}{
		"rotation_period": json.Number("30"),
		"ttl":             json.Number("5"),
	}

	nonRenewableRotated = Secret{LeaseDuration: 100, Data: data}
	nonRenewableRotatedDur = leaseCheckWait(&nonRenewableRotated).Seconds()

	// We expect a 1 second cushion
	if nonRenewableRotatedDur != 6 {
		t.Fatalf("renewable duration is not 6: %f", nonRenewableRotatedDur)
	}

	rawExpiration := time.Now().Unix() + 100
	expiration := strconv.FormatInt(rawExpiration, 10)

	data = map[string]interface{}{
		"expiration":  json.Number(expiration),
		"certificate": "foobar",
	}

	nonRenewableCert := Secret{LeaseDuration: 100, Data: data}
	nonRenewableCertDur := leaseCheckWait(&nonRenewableCert).Seconds()
	if nonRenewableCertDur < 80 || nonRenewableCertDur > 95 {
		t.Fatalf("non renewable certificate duration is not within 80%% to 95%%: %f", nonRenewableCertDur)
	}

	t.Run("secret ID handling", func(t *testing.T) {
		t.Run("normal case", func(t *testing.T) {
			// Secret ID TTL handling
			data := map[string]interface{}{
				"secret_id":     "abc",
				"secret_id_ttl": json.Number("60"),
			}

			nonRenewableSecretID := Secret{LeaseDuration: 100, Data: data}
			nonRenewableSecretIDDur := leaseCheckWait(&nonRenewableSecretID).Seconds()

			if nonRenewableSecretIDDur < 0.80*(60+1) || nonRenewableSecretIDDur > 0.95*(60+1) {
				t.Fatalf("renewable duration is not within 80%% to 95%% of lease duration: %f", nonRenewableSecretIDDur)
			}
		})

		t.Run("0 ttl", func(t *testing.T) {
			const leaseDuration = 1000

			data := map[string]interface{}{
				"secret_id":     "abc",
				"secret_id_ttl": json.Number("0"),
			}

			nonRenewableSecretID := Secret{LeaseDuration: leaseDuration, Data: data}
			nonRenewableSecretIDDur := leaseCheckWait(&nonRenewableSecretID).Seconds()

			if nonRenewableSecretIDDur < 0.80*(leaseDuration+1) || nonRenewableSecretIDDur > 0.95*(leaseDuration+1) {
				t.Fatalf("renewable duration is not within 80%% to 95%% of lease duration: %f", nonRenewableSecretIDDur)
			}
		})

		t.Run("ttl missing", func(t *testing.T) {
			const leaseDuration = 1000

			data := map[string]interface{}{
				"secret_id": "abc",
			}

			nonRenewableSecretID := Secret{LeaseDuration: leaseDuration, Data: data}
			nonRenewableSecretIDDur := leaseCheckWait(&nonRenewableSecretID).Seconds()

			if nonRenewableSecretIDDur < 0.80*(leaseDuration+1) || nonRenewableSecretIDDur > 0.95*(leaseDuration+1) {
				t.Fatalf("renewable duration is not within 80%% to 95%% of lease duration: %f", nonRenewableSecretIDDur)
			}
		})
	})
}

func setupVaultPKI(clients *ClientSet) {
	err := clients.Vault().Sys().Mount("pki", &api.MountInput{
		Type: "pki",
	})
	switch {
	case err == nil:
	case strings.Contains(err.Error(), "path is already in use"):
		// for idempotency
		return
	default:
		panic(err)
	}

	vc := clients.Vault()

	_, err = vc.Logical().Write("pki/root/generate/internal",
		map[string]interface{}{
			"common_name": "example.com",
			"ttl":         "48h",
		})
	if err != nil {
		panic(err)
	}

	for needCA, count := true, 0; needCA && count < 5; count++ {
		l, err := vc.Logical().List("pki/keys")
		if err != nil && !strings.Contains(err.Error(), "connection refused") {
			panic(err)
		}
		if l != nil {
			needCA = false
		}
		time.Sleep(time.Millisecond)
	}

	_, err = vc.Logical().Write("pki/roles/example-dot-com",
		map[string]interface{}{
			"allowed_domains":     "example.com",
			"allow_subdomains":    "true",
			"not_before_duration": "1s",
		})
	if err != nil {
		panic(err)
	}
}
