// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// The library of service accounts that can be checked out
// is a discrete set of features. This test suite provides
// end-to-end tests of these interrelated endpoints.
func TestCheckOuts(t *testing.T) {
	ctx := context.Background()
	b, s := getBackend(t, false)
	defer b.Cleanup(ctx)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   s,
		Data: map[string]interface{}{
			"binddn":   "euclid",
			"password": "password",
			"url":      "ldap://ldap.forumsys.com:389",
			"userdn":   "cn=read-only-admin,dc=example,dc=com",
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}

	// Exercise all set endpoints.
	t.Run("write set", WriteSet(b, s))
	t.Run("read set", ReadSet(b, s))
	t.Run("read set status", ReadSetStatus(b, s))
	t.Run("write set toggle off", WriteSetToggleOff(b, s))
	t.Run("read set toggle off", ReadSetToggleOff(b, s))
	t.Run("write conflicting set", WriteSetWithConflictingServiceAccounts(b, s))
	t.Run("list sets", ListSets(b, s))
	t.Run("delete set", DeleteSet(b, s))

	// Do some common updates on sets and ensure they work.
	t.Run("write set", WriteSet(b, s))
	t.Run("add service account", AddAnotherServiceAccount(b, s))
	t.Run("remove service account", RemoveServiceAccount(b, s))

	t.Run("check initial status", CheckInitialStatus(b, s))
	t.Run("check out account", PerformCheckOut(b, s))
	t.Run("check updated status", CheckUpdatedStatus(b, s))
	t.Run("normal check in", NormalCheckIn(b, s))
	t.Run("return to initial status", CheckInitialStatus(b, s))
	t.Run("check out again", PerformCheckOut(b, s))
	t.Run("check updated status", CheckUpdatedStatus(b, s))
	t.Run("force check in", ForceCheckIn(b, s))
	t.Run("check all are available", CheckInitialStatus(b, s))
}

// TestCheckOutRaces executes a whole bunch of calls at once and only looks for
// races. Responses are ignored because they'll vary depending on execution order.
func TestCheckOutRaces(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping check for races in the checkout system due to short flag")
	}

	ctx := context.Background()
	b, s := getBackend(t, false)
	defer b.Cleanup(ctx)

	// Get 100 goroutines ready to go.
	numParallel := 100
	start := make(chan bool, 1)
	end := make(chan bool, numParallel)
	for i := 0; i < numParallel; i++ {
		go func() {
			<-start
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.CreateOperation,
				Path:      libraryPrefix + "test-set",
				Storage:   s,
				Data: map[string]interface{}{
					"service_account_names":        []string{"tester1@example.com", "tester2@example.com"},
					"ttl":                          "10h",
					"max_ttl":                      "11h",
					"disable_check_in_enforcement": true,
				},
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      libraryPrefix + "test-set",
				Storage:   s,
				Data: map[string]interface{}{
					"service_account_names": []string{"tester1@example.com", "tester2@example.com", "tester3@example.com"},
				},
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      libraryPrefix + "test-set",
				Storage:   s,
				Data: map[string]interface{}{
					"service_account_names": []string{"tester1@example.com", "tester2@example.com"},
				},
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "test-set",
				Storage:   s,
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      libraryPrefix + "test-set",
				Storage:   s,
				Data: map[string]interface{}{
					"service_account_names":        []string{"tester1@example.com", "tester2@example.com"},
					"ttl":                          "10h",
					"disable_check_in_enforcement": false,
				},
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "test-set",
				Storage:   s,
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "test-set/status",
				Storage:   s,
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.CreateOperation,
				Path:      libraryPrefix + "test-set2",
				Storage:   s,
				Data: map[string]interface{}{
					"service_account_names": "tester1@example.com",
				},
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ListOperation,
				Path:      libraryPrefix,
				Storage:   s,
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.DeleteOperation,
				Path:      libraryPrefix + "test-set",
				Storage:   s,
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "test-set/status",
				Storage:   s,
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "test-set/check-out",
				Storage:   s,
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "test-set/status",
				Storage:   s,
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "test-set/check-in",
				Storage:   s,
			})
			b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "manage/test-set/check-in",
				Storage:   s,
			})
			end <- true
		}()
	}

	// Start them all at once.
	close(start)

	// Wait for them all to finish.
	timer := time.NewTimer(15 * time.Second)
	for i := 0; i < numParallel; i++ {
		select {
		case <-timer.C:
			t.Fatal("test took more than 15 seconds, may be deadlocked")
		case <-end:
			continue
		}
	}
}

func WriteSet(b logical.Backend, s logical.Storage) func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      libraryPrefix + "test-set",
			Storage:   s,
			Data: map[string]interface{}{
				"service_account_names":        []string{"tester1@example.com", "tester2@example.com"},
				"ttl":                          "10h",
				"max_ttl":                      "11h",
				"disable_check_in_enforcement": true,
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatal(err)
		}
		if resp != nil {
			t.Fatalf("expected an empty response, got: %v", resp)
		}
	}
}

func AddAnotherServiceAccount(b logical.Backend, s logical.Storage) func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      libraryPrefix + "test-set",
			Storage:   s,
			Data: map[string]interface{}{
				"service_account_names": []string{"tester1@example.com", "tester2@example.com", "tester3@example.com"},
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatal(err)
		}
		if resp != nil {
			t.Fatalf("expected an empty response, got: %v", resp)
		}
	}
}

func RemoveServiceAccount(b logical.Backend, s logical.Storage) func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      libraryPrefix + "test-set",
			Storage:   s,
			Data: map[string]interface{}{
				"service_account_names": []string{"tester1@example.com", "tester2@example.com"},
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatal(err)
		}
		if resp != nil {
			t.Fatalf("expected an empty response, got: %v", resp)
		}
	}
}

func ReadSet(b logical.Backend, s logical.Storage) func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      libraryPrefix + "test-set",
			Storage:   s,
		}
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected a response")
		}
		serviceAccountNames := resp.Data["service_account_names"].([]string)
		if len(serviceAccountNames) != 2 {
			t.Fatal("expected 2")
		}
		disableCheckInEnforcement := resp.Data["disable_check_in_enforcement"].(bool)
		if !disableCheckInEnforcement {
			t.Fatal("check-in enforcement should be disabled")
		}
		ttl := resp.Data["ttl"].(int64)
		if ttl != 10*60*60 { // 10 hours
			t.Fatal(ttl)
		}
		maxTTL := resp.Data["max_ttl"].(int64)
		if maxTTL != 11*60*60 { // 11 hours
			t.Fatal(maxTTL)
		}
	}
}

func WriteSetToggleOff(b logical.Backend, s logical.Storage) func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      libraryPrefix + "test-set",
			Storage:   s,
			Data: map[string]interface{}{
				"service_account_names":        []string{"tester1@example.com", "tester2@example.com"},
				"ttl":                          "10h",
				"disable_check_in_enforcement": false,
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatal(err)
		}
		if resp != nil {
			t.Fatalf("expected an empty response, got: %v", resp)
		}
	}
}

func ReadSetToggleOff(b logical.Backend, s logical.Storage) func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      libraryPrefix + "test-set",
			Storage:   s,
		}
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected a response")
		}
		serviceAccountNames := resp.Data["service_account_names"].([]string)
		if len(serviceAccountNames) != 2 {
			t.Fatal("expected 2")
		}
		disableCheckInEnforcement := resp.Data["disable_check_in_enforcement"].(bool)
		if disableCheckInEnforcement {
			t.Fatal("check-in enforcement should be enabled")
		}
	}
}

func ReadSetStatus(b logical.Backend, s logical.Storage) func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      libraryPrefix + "test-set/status",
			Storage:   s,
		}
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected a response")
		}
		if len(resp.Data) != 2 {
			t.Fatal("length should be 2 because there are two service accounts in this set")
		}
		if resp.Data["tester1@example.com"] == nil {
			t.Fatal("expected non-nil map")
		}
		testerStatus := resp.Data["tester1@example.com"].(map[string]interface{})
		if !testerStatus["available"].(bool) {
			t.Fatal("should be available for checkout")
		}
	}
}

func WriteSetWithConflictingServiceAccounts(b logical.Backend, s logical.Storage) func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      libraryPrefix + "test-set2",
			Storage:   s,
			Data: map[string]interface{}{
				"service_account_names": "tester1@example.com",
			},
		}
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil || !resp.IsError() {
			t.Fatal("expected err response because we're adding a service account managed by another set")
		}
	}
}

func ListSets(b logical.Backend, s logical.Storage) func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.ListOperation,
			Path:      libraryPrefix,
			Storage:   s,
		}
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected a response")
		}
		if resp.Data["keys"] == nil {
			t.Fatal("expected non-nil data")
		}
		listedKeys := resp.Data["keys"].([]string)
		if len(listedKeys) != 1 {
			t.Fatalf("expected 1 key but received %s", listedKeys)
		}
		if listedKeys[0] != "test-set" {
			t.Fatal("expected test-set to be the only listed item")
		}
	}
}

func DeleteSet(b logical.Backend, s logical.Storage) func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      libraryPrefix + "test-set",
			Storage:   s,
		}
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatal(err)
		}
		if resp != nil {
			t.Fatalf("expected an empty response, got: %v", resp)
		}
	}
}

func CheckInitialStatus(b logical.Backend, s logical.Storage) func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      libraryPrefix + "test-set/status",
			Storage:   s,
		}
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected a response")
		}
		if resp.Data["tester1@example.com"] == nil {
			t.Fatal("expected map to not be nil")
		}
		tester1CheckOut := resp.Data["tester1@example.com"].(map[string]interface{})
		available := tester1CheckOut["available"].(bool)
		if !available {
			t.Fatal("tester1 should be available")
		}

		if resp.Data["tester2@example.com"] == nil {
			t.Fatal("expected map to not be nil")
		}
		tester2CheckOut := resp.Data["tester2@example.com"].(map[string]interface{})
		available = tester2CheckOut["available"].(bool)
		if !available {
			t.Fatal("tester2 should be available")
		}
	}
}

func PerformCheckOut(b logical.Backend, s logical.Storage) func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      libraryPrefix + "test-set/check-out",
			Storage:   s,
		}
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected a response")
		}
		if resp.Data == nil {
			t.Fatal("expected resp data to not be nil")
		}

		if resp.Data["service_account_name"] == nil {
			t.Fatal("expected string to be populated")
		}
		if resp.Data["service_account_name"].(string) == "" {
			t.Fatal("service account name should be populated")
		}
		if resp.Data["password"].(string) == "" {
			t.Fatal("password should be populated")
		}
		if !resp.Secret.Renewable {
			t.Fatal("lease should be renewable")
		}
		if resp.Secret.TTL != time.Hour*10 {
			t.Fatal("expected 10h TTL")
		}
		if resp.Secret.MaxTTL != time.Hour*11 {
			t.Fatal("expected 11h TTL")
		}
		if resp.Secret.InternalData["service_account_name"].(string) == "" {
			t.Fatal("internal service account name should not be empty")
		}
	}
}

func CheckUpdatedStatus(b logical.Backend, s logical.Storage) func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      libraryPrefix + "test-set/status",
			Storage:   s,
		}
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected a response")
		}
		if resp.Data == nil {
			t.Fatal("expected data to not be nil")
		}

		if resp.Data["tester1@example.com"] == nil {
			t.Fatal("expected map to not be nil")
		}
		tester1CheckOut := resp.Data["tester1@example.com"].(map[string]interface{})
		tester1Available := tester1CheckOut["available"].(bool)

		if resp.Data["tester2@example.com"] == nil {
			t.Fatal("expected map to not be nil")
		}
		tester2CheckOut := resp.Data["tester2@example.com"].(map[string]interface{})
		tester2Available := tester2CheckOut["available"].(bool)

		if tester1Available && tester2Available {
			t.Fatal("one of the testers should not be available")
		}
	}
}

func NormalCheckIn(b logical.Backend, s logical.Storage) func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      libraryPrefix + "test-set/check-in",
			Storage:   s,
		}
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected a response")
		}
		checkIns := resp.Data["check_ins"].([]string)
		if len(checkIns) != 1 {
			t.Fatal("expected 1 check-in")
		}
	}
}

func ForceCheckIn(b logical.Backend, s logical.Storage) func(t *testing.T) {
	return func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      libraryPrefix + "manage/test-set/check-in",
			Storage:   s,
		}
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected a response")
		}
		checkIns := resp.Data["check_ins"].([]string)
		if len(checkIns) != 1 {
			t.Fatal("expected 1 check-in")
		}
	}
}

func Test_librarySet_Validate(t *testing.T) {
	tests := []struct {
		name    string
		set     *librarySet
		wantErr bool
	}{
		{
			name: "valid library set",
			set: &librarySet{
				ServiceAccountNames: []string{"name1"},
				TTL:                 time.Minute,
				MaxTTL:              2 * time.Minute,
			},
		},
		{
			name: "invalid library set with empty list of service account names",
			set: &librarySet{
				ServiceAccountNames: []string{},
				TTL:                 time.Minute,
				MaxTTL:              2 * time.Minute,
			},
			wantErr: true,
		},
		{
			name: "invalid library set with empty service account name",
			set: &librarySet{
				ServiceAccountNames: []string{""},
				TTL:                 time.Minute,
				MaxTTL:              2 * time.Minute,
			},
			wantErr: true,
		},
		{
			name: "invalid library set with max TTL less than TTL",
			set: &librarySet{
				ServiceAccountNames: []string{"name1", "name2"},
				TTL:                 2 * time.Minute,
				MaxTTL:              time.Minute,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.set.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
