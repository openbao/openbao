package assert

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

// HttpStatusEquals compares an expected HTTP Status with an actual response,
// and when this test fails, then the HTTP Body is inspected and logged.
func HttpStatusEqual(t *testing.T, r *http.Response, code int) {
	t.Helper()

	if r.StatusCode != code {
		defer r.Body.Close()
		body, bodyErr := io.ReadAll(r.Body)
		if bodyErr != nil {
			t.Fatal(bodyErr)
		}
		body = bytes.TrimSpace(body)

		t.Errorf(
			"actual HTTP status: %d; expectation: %d\nURL: %s\nBody: %s\n",
			r.StatusCode, code, r.Request.URL, string(body),
		)
	}
}
