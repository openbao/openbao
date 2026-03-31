package logical

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateOperation(t *testing.T) {
	testCases := []struct {
		title string
		input []Operation
		wantErr bool
	}{
		{
			title: "Single matching operation",
			input: []Operation{ ReadOperation },
			wantErr: false,
		},
		{
			title: "Multiple matching operations",
			input: []Operation{ ReadOperation, PatchOperation },
			wantErr: false,
		},
		{
			title: "Single non-matching operation",
			input: []Operation{ Operation("not-match") },
			wantErr: true,
		},
		{
			title: "Multiple non-matching operations",
			input: []Operation{ ReadOperation, Operation("not-match")},
			wantErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			err := ValidateOperation(tc.input...)
			if tc.wantErr {
				assert.Error(t, err, "expected error for ValidateOperation")
			} else {
				assert.NoError(t, err, "expected no error for ValidateOperation")
			}
		})
	}
}
