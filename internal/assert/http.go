package assert

import (
	"bytes"
	"encoding/json"
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

func HttpJsonResponse(t *testing.T, r *http.Response, out any) {
	if r == nil {
		t.Fatalf("HTTP Response missing!")
	}
	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	decoder.UseNumber()
	decodingErr := decoder.Decode(out)
	if decodingErr != nil {
		t.Errorf("Error decoding JSON from HTTP Response: %s", decodingErr)
	}
}
