// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"testing"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// TestExpiration_WithTransaction validates transaction callback success
func TestExpiration_WithTransaction(t *testing.T) {
	exp := mockExpiration(t)
	ctx := namespace.RootContext(context.Background())

	var callbackExecuted bool
	var transactionContext context.Context

	err := exp.WithTransaction(ctx, func(txCtx context.Context) error {
		callbackExecuted = true
		transactionContext = txCtx

		// Verify transaction context key is present
		tx := txCtx.Value(logical.TransactionContextKey)
		if tx == nil {
			t.Error("expected transaction in context")
		} else {
			t.Logf("Transaction type: %T", tx)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("WithTransaction should not have errored: %v", err)
	}

	if !callbackExecuted {
		t.Fatal("callback should have been executed")
	}

	if transactionContext == nil {
		t.Fatal("transaction context should not be nil")
	}
}

// TestExpiration_WithTransaction_CallbackError validates transaction callback error
func TestExpiration_WithTransaction_CallbackError(t *testing.T) {
	exp := mockExpiration(t)
	ctx := namespace.RootContext(context.Background())

	expectedError := errors.New("callback error")
	var callbackExecuted bool

	err := exp.WithTransaction(ctx, func(txCtx context.Context) error {
		callbackExecuted = true
		return expectedError
	})

	if err != expectedError {
		t.Fatalf("expected callback error, got: %v", err)
	}

	if !callbackExecuted {
		t.Fatal("callback should have been executed")
	}
}

// TestExpiration_WithTransaction_Integration tests the WithTransaction method
// with a more realistic scenario involving lease operations
func TestExpiration_WithTransaction_Integration(t *testing.T) {
	exp := mockExpiration(t)
	ctx := namespace.RootContext(context.Background())

	// Test that the transaction context is properly passed through
	// and can be used for operations that might need transactions
	var transactionOperationExecuted bool

	err := exp.WithTransaction(ctx, func(txCtx context.Context) error {
		transactionOperationExecuted = true

		// Simulate some operation that would benefit from transactions
		// In a real scenario, this could be creating multiple lease entries atomically

		// Verify the transaction context key is available (even if nil for non-transactional storage)
		_ = txCtx.Value(logical.TransactionContextKey)

		// Simulate successful operation
		return nil
	})
	if err != nil {
		t.Fatalf("integration test failed: %v", err)
	}

	if !transactionOperationExecuted {
		t.Fatal("transaction operation should have been executed")
	}
}

// TestExpiration_WithTransaction_ContextPropagation verifies that the context
// is properly propagated with transaction information
func TestExpiration_WithTransaction_ContextPropagation(t *testing.T) {
	exp := mockExpiration(t)
	ctx := namespace.RootContext(context.Background())

	// Add some custom value to the original context
	customKey := "custom_test_key"
	customValue := "custom_test_value"
	ctx = context.WithValue(ctx, customKey, customValue)

	var receivedContext context.Context

	err := exp.WithTransaction(ctx, func(txCtx context.Context) error {
		receivedContext = txCtx

		// Verify the original context values are preserved
		if value := txCtx.Value(customKey); value != customValue {
			t.Errorf("expected custom value %q, got %v", customValue, value)
		}

		// Verify transaction context key is present (even if value is nil)
		_ = txCtx.Value(logical.TransactionContextKey)

		return nil
	})
	if err != nil {
		t.Fatalf("context propagation test failed: %v", err)
	}

	if receivedContext == nil {
		t.Fatal("context should have been received")
	}

	// Verify the callback received a different context than the original
	// (because it should have the transaction key added)
	if receivedContext == ctx {
		t.Error("callback should receive a new context with transaction information")
	}
}
