package certutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetHexFormatted(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		desc    string
		input   []byte
		sep     string
		wantOut string
	}{
		{
			desc:    "nil input",
			input:   nil,
			sep:     "",
			wantOut: "",
		},
		{
			desc:    "Empty input",
			input:   []byte(""),
			sep:     "",
			wantOut: "",
		},
		{
			desc:    "Single character",
			input:   []byte{0x61},
			sep:     ":",
			wantOut: "61",
		},
		{
			desc:    "Multiple bytes",
			input:   []byte{0x61, 0x62, 0x63, 0x64},
			sep:     ":",
			wantOut: "61:62:63:64",
		},
		{
			desc:    "Leading 0s",
			input:   []byte{0x00, 0x01, 0x02, 0x0f},
			sep:     ":",
			wantOut: "00:01:02:0f",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := GetHexFormatted(tc.input, tc.sep)

			assert.Equal(t, tc.wantOut, got)
		})
	}
}

func TestParseHexFormatted(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		desc    string
		input   string
		sep     string
		wantOut []byte
	}{
		{
			desc:    "Empty input",
			input:   "",
			sep:     ":",
			wantOut: nil,
		},
		{
			desc:    "Single hexadecimal byte",
			input:   "0",
			sep:     "",
			wantOut: []byte{0x00},
		},
		{
			desc:    "Maximum hexadecimal value",
			input:   "f",
			sep:     "",
			wantOut: []byte{0xf},
		},
		{
			desc:    "Two bytes without separator",
			input:   "ff",
			sep:     "",
			wantOut: []byte{0xf, 0xf},
		},
		{
			desc:    "Two bytes with separator",
			input:   "0:1",
			sep:     ":",
			wantOut: []byte{0x00, 0x01},
		},
		{
			desc:    "Case sensitive",
			input:   "0:1:F",
			sep:     ":",
			wantOut: []byte{0x00, 0x01, 0x0f},
		},
		{
			desc:    "Invalid hexadecimal",
			input:   "0:z",
			sep:     ":",
			wantOut: nil,
		},
		{
			desc:    "Empty segments",
			input:   "0::1",
			sep:     ":",
			wantOut: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := ParseHexFormatted(tc.input, tc.sep)

			assert.Equal(t, tc.wantOut, got)
		})
	}
}
