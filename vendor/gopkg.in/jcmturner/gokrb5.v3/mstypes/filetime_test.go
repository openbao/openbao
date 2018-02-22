package mstypes

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestFileTime(t *testing.T) {
	//2007-02-22 17:00:01.6382155
	tt := time.Date(2007, 2, 22, 17, 0, 1, 638215500, time.UTC)
	ft := GetFileTime(tt)
	assert.Equal(t, tt.Unix(), ft.Unix(), "Unix epoch time not as expected")
	assert.Equal(t, int64(128166372016382155), ft.MSEpoch(), "MSEpoch not as expected")
	assert.Equal(t, tt, ft.Time(), "Golang time object returned from FileTime not as expected")
}
