package framework

import (
	"testing"
	"time"
)

func TestActionGateTokenPolicy_AuthorizeTokenIssuance(t *testing.T) {
	policy := NewActionGateTokenPolicy(5 * time.Minute)

	// 1. Standard non-destructive tool action
	allowed, hash1, err := policy.AuthorizeTokenIssuance("agent_reader", "db_select", "", false)
	if err != nil || !allowed || hash1 == "" {
		t.Fatalf("Expected non-destructive action to pass, got err: %v", err)
	}

	// 2. Destructive action without prove token fails
	allowed, _, err = policy.AuthorizeTokenIssuance("agent_writer", "db_drop_table", "", true)
	if err == nil || allowed {
		t.Fatalf("Expected destructive action without prove token to fail, got allowed")
	}

	// 3. Destructive action with valid prove token passes
	allowed, hash3, err := policy.AuthorizeTokenIssuance("agent_admin", "db_drop_table", "prov_live_1234567890abcdef1234567890abcdef", true)
	if err != nil || !allowed || hash3 == "" {
		t.Fatalf("Expected authorized prove token to pass, got err: %v", err)
	}

	// 4. Verify cryptographic hash chain integrity
	entries := policy.Ledger.GetEntries()
	if len(entries) != 3 {
		t.Fatalf("Expected 3 ledger entries, got %d", len(entries))
	}
	if !policy.Ledger.VerifyIntegrity() {
		t.Fatalf("Expected ledger integrity verification to pass")
	}
}
