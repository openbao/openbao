package jwtauth

import (
	"errors"
	"testing"
)

func TestParseHelp(t *testing.T) {
	tests := []struct {
		name    string
		err     string
		summary string
		detail  string
	}{
		{
			err:     "",
			summary: "",
			detail:  "",
		},
		{
			err:     "No error text",
			summary: "",
			detail:  "",
		},
		{
			err:     "Errors: * This is an error.",
			summary: "Login error",
			detail:  "This is an error.",
		},
		{
			err:     "Errors: * Vault login failed. Because of reasons.",
			summary: "Vault login failed.",
			detail:  "Because of reasons.",
		},
		{
			err:     "Errors: * Token verification failed. Because of reasons.",
			summary: "Token verification failed.",
			detail:  "Because of reasons.",
		},
		{
			err:     "Errors: * No response from provider. Because of reasons.",
			summary: "No response from provider.",
			detail:  "Because of reasons.",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, d := parseError(errors.New(test.err))
			if s != test.summary {
				t.Fatalf("expected summary: %q, got: %q", test.summary, s)
			}
			if d != test.detail {
				t.Fatalf("expected detail: %q, got: %q", test.detail, d)
			}

		})
	}
}
