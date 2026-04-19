package certutil

import "testing"

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
