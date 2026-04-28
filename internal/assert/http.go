package assert

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	HeaderContent = "Content-Type"
	HttpJSON      = "application/json"
)

type httpErrResponses struct {
	Errors []string `json:"errors"`
}

func (e *httpErrResponses) AddErrors(err error) {
	e.Errors = append(e.Errors, err.Error())
}

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

// changeHttpStatusToMatchError will change the HTTP Status associated with
// errors. This private test func is written to leverage the errors.Is() and
// errors.As() methods that became available in the STDLIB 9/2019, and avoid
// relying on the go-multierror pkg imported in the Logical pkg in 2/2017.
func changeHttpStatusToMatchError(status *int, err error) {
	var hce = logical.CodedError(0, "")
	switch {
	case errors.Is(err, consts.ErrSealed),
		errors.Is(err, consts.ErrNamespaceSealed),
		errors.Is(err, consts.ErrAPILocked):
		*status = http.StatusServiceUnavailable
	case strings.Contains(err.Error(), "http: request body too large"):
		*status = http.StatusRequestEntityTooLarge
	case errors.As(err, &hce):
		httpCodedErr, ok := err.(logical.HTTPCodedError)
		if ok {
			*status = httpCodedErr.Code()
		}
	}
}

// HttpErrorResponse creates an Error for tests.
func HttpErrorResponse(w http.ResponseWriter, status int, err error) {
	changeHttpStatusToMatchError(&status, err)

	// Set a JSON header
	w.Header().Set(HeaderContent, HttpJSON)
	w.WriteHeader(status)

	// Create a struct to hold an error.
	errResponse := &httpErrResponses{
		Errors: make([]string, 0, 1),
	}

	if err != nil {
		errResponse.AddErrors(err)
	}

	jsonEncoding := json.NewEncoder(w)
	jsonEncoding.Encode(errResponse)
}
