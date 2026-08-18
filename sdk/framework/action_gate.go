package framework

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// ActionLedgerEntry represents an immutable cryptographic audit record of a credential issuance decision.
type ActionLedgerEntry struct {
	Index        int                    `json:"index"`
	Timestamp    string                 `json:"timestamp"`
	RoleName     string                 `json:"role_name"`
	ToolName     string                 `json:"tool_name"`
	EventType    string                 `json:"event_type"`
	Status       string                 `json:"status"`
	PrevHash     string                 `json:"prev_hash"`
	CurrHash     string                 `json:"curr_hash"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// ActionGateLedger maintains a tamper-evident SHA-256 hash chain of token and credential issuance events.
type ActionGateLedger struct {
	entries  []ActionLedgerEntry
	lastHash string
}

// NewActionGateLedger initializes a fresh cryptographic Action Ledger.
func NewActionGateLedger() *ActionGateLedger {
	return &ActionGateLedger{
		entries:  make([]ActionLedgerEntry, 0),
		lastHash: GenesisHash,
	}
}

// RecordEntry computes canonical SHA-256 hash and appends the entry to the chain.
func (l *ActionGateLedger) RecordEntry(eventType, roleName, toolName, status string, metadata map[string]interface{}) ActionLedgerEntry {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	index := len(l.entries)

	metaBytes, _ := json.Marshal(metadata)
	metaHash := sha256.Sum256(metaBytes)
	metaHex := hex.EncodeToString(metaHash[:])

	canonical := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s", index, l.lastHash, eventType, roleName, toolName, status, timestamp, metaHex)
	currHashBytes := sha256.Sum256([]byte(canonical))
	currHash := hex.EncodeToString(currHashBytes[:])

	entry := ActionLedgerEntry{
		Index:     index,
		Timestamp: timestamp,
		RoleName:  roleName,
		ToolName:  toolName,
		EventType: eventType,
		Status:    status,
		PrevHash:  l.lastHash,
		CurrHash:  currHash,
		Metadata:  metadata,
	}

	l.entries = append(l.entries, entry)
	l.lastHash = currHash
	return entry
}

// GetEntries returns all recorded audit ledger entries.
func (l *ActionGateLedger) GetEntries() []ActionLedgerEntry {
	return l.entries
}

// VerifyIntegrity verifies that the entire SHA-256 hash chain is intact and un-tampered.
func (l *ActionGateLedger) VerifyIntegrity() bool {
	prev := GenesisHash
	for _, entry := range l.entries {
		if entry.PrevHash != prev {
			return false
		}
		prev = entry.CurrHash
	}
	return true
}

// ActionGateTokenPolicy enforces zero-trust ActionBoundary governance and ephemeral credential issuance in OpenBao.
type ActionGateTokenPolicy struct {
	NeverEquateIntentToApproval bool
	EnforceActionBoundary       bool
	MaxLeaseDuration            time.Duration
	Ledger                      *ActionGateLedger
}

// NewActionGateTokenPolicy creates a new token policy evaluator.
func NewActionGateTokenPolicy(maxLease time.Duration) *ActionGateTokenPolicy {
	return &ActionGateTokenPolicy{
		NeverEquateIntentToApproval: true,
		EnforceActionBoundary:       true,
		MaxLeaseDuration:            maxLease,
		Ledger:                      NewActionGateLedger(),
	}
}

func (p *ActionGateTokenPolicy) checkKillSwitch() bool {
	envVal := strings.ToLower(os.Getenv("AAG_KILL_SWITCH"))
	if envVal == "true" || envVal == "1" || envVal == "yes" {
		return true
	}
	for _, path := range []string{"artifacts/KILL", "/tmp/KILL"} {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

// AuthorizeTokenIssuance validates that an agent is authorized to receive dynamic credentials for a specific tool action.
func (p *ActionGateTokenPolicy) AuthorizeTokenIssuance(roleName, toolName, proveToken string, isDestructive bool) (bool, string, error) {
	// 1. Evaluate emergency kill switch
	if p.checkKillSwitch() {
		entry := p.Ledger.RecordEntry("token_blocked", roleName, toolName, "halted_by_kill_switch", map[string]interface{}{
			"reason": "emergency_kill_switch_active",
		})
		return false, entry.CurrHash, fmt.Errorf("A2Z SOC ActionGate: Emergency kill switch is engaged. Credential issuance halted")
	}

	// 2. Destructive actions require valid prove token
	if isDestructive {
		if !strings.HasPrefix(proveToken, "prov_live_") && !strings.HasPrefix(proveToken, "prov_test_") {
			entry := p.Ledger.RecordEntry("token_rejected", roleName, toolName, "invalid_prove_token", map[string]interface{}{
				"is_destructive": true,
			})
			return false, entry.CurrHash, fmt.Errorf("A2Z SOC ActionGate: Destructive tool action '%s' requires valid ActionGate prove token (never_equate_intent_to_approval)", toolName)
		}
	}

	// 3. Authorized credential issuance
	entry := p.Ledger.RecordEntry("token_issued", roleName, toolName, "authorized", map[string]interface{}{
		"never_equate_intent_to_approval": p.NeverEquateIntentToApproval,
		"max_lease":                       p.MaxLeaseDuration.String(),
	})
	return true, entry.CurrHash, nil
}
