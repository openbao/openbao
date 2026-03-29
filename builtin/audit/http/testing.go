// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"
)

func GetTestAuditHandler(t *testing.T, lock *sync.Mutex, logs *[]map[string]interface{}, path string, requiredHeaders http.Header, badRequests *int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		lock.Lock()
		defer lock.Unlock()
		t.Logf("got request: %#v", r)

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if r.URL.Path != path {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		for header, allowedValues := range requiredHeaders {
			actualValues := r.Header.Values(header)
			if len(actualValues) == 0 {
				t.Logf("missing expected header: %v", header)
				*badRequests += 1
				w.WriteHeader(http.StatusForbidden)
				return
			}

			for _, value := range actualValues {
				var found bool
				for _, allowedValue := range allowedValues {
					if allowedValue == value {
						found = true
					}
				}

				if !found {
					t.Logf("value %v is not allowed for header %v", value, header)
					*badRequests += 1
					w.WriteHeader(http.StatusForbidden)
					return
				}
			}
		}

		var log map[string]interface{}
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&log); err != nil {
			t.Logf("failed to decode request: %v", err)
			*badRequests += 1
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		*logs = append(*logs, log)
		t.Logf("adding log: %v", log)

		w.WriteHeader(http.StatusOK)
	}
}
