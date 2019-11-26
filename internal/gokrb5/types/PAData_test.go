package types

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/iana/patype"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/test/testdata"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalPADataSequence(t *testing.T) {
	t.Parallel()
	var a PADataSequence
	b, err := hex.DecodeString(testdata.MarshaledKRB5padata_sequence)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, 2, len(a), "Number of PAData items in the sequence not as expected")
	for i, pa := range a {
		assert.Equal(t, patype.PA_SAM_RESPONSE, pa.PADataType, fmt.Sprintf("PAData type for entry %d not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_PADATA_VALUE), pa.PADataValue, fmt.Sprintf("PAData valye for entry %d not as expected", i+1))
	}
}

func TestUnmarshalPADataSequence_empty(t *testing.T) {
	t.Parallel()
	var a PADataSequence
	b, err := hex.DecodeString(testdata.MarshaledKRB5padataSequenceEmpty)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, 0, len(a), "Number of PAData items in the sequence not as expected")
}

func TestUnmarshalPAEncTSEnc(t *testing.T) {
	t.Parallel()
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	var a PAEncTSEnc
	b, err := hex.DecodeString(testdata.MarshaledKRB5pa_enc_ts)
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", "MarshaledKRB5pa_enc_ts", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", "MarshaledKRB5pa_enc_ts", err)
	}
	assert.Equal(t, tt, a.PATimestamp, "PA timestamp not as expected")
	assert.Equal(t, 123456, a.PAUSec, "PA microseconds not as expected")
}

func TestUnmarshalPAEncTSEnc_nousec(t *testing.T) {
	t.Parallel()
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	var a PAEncTSEnc
	b, err := hex.DecodeString(testdata.MarshaledKRB5pa_enc_tsNoUsec)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, tt, a.PATimestamp, "PA timestamp not as expected")
	assert.Equal(t, 0, a.PAUSec, "PA microseconds not as expected")
}

func TestUnmarshalETypeInfo(t *testing.T) {
	t.Parallel()
	var a ETypeInfo
	b, err := hex.DecodeString(testdata.MarshaledKRB5etype_info)
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", "MarshaledKRB5etype_info", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", "MarshaledKRB5etype_info", err)
	}
	assert.Equal(t, 3, len(a), "Number of EType info entries not as expected")
	assert.Equal(t, int32(0), a[0].EType, "Etype of first etype info entry not as expected")
	assert.Equal(t, []byte("Morton's #0"), a[0].Salt, "Salt of first etype info entry not as expected")
	assert.Equal(t, int32(1), a[1].EType, "Etype of second etype info entry not as expected")
	assert.Equal(t, 0, len(a[1].Salt), "Salt of second etype info entry not as expected")
	assert.Equal(t, int32(2), a[2].EType, "Etype of third etype info entry not as expected")
	assert.Equal(t, []byte("Morton's #2"), a[2].Salt, "Salt of third etype info entry not as expected")
}

func TestUnmarshalETypeInfo_only1(t *testing.T) {
	t.Parallel()
	var a ETypeInfo
	b, err := hex.DecodeString(testdata.MarshaledKRB5etype_infoOnly1)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, 1, len(a), "Number of EType info entries not as expected")
	assert.Equal(t, int32(0), a[0].EType, "Etype of first etype info entry not as expected")
	assert.Equal(t, []byte("Morton's #0"), a[0].Salt, "Salt of first etype info entry not as expected")
}

func TestUnmarshalETypeInfo_noinfo(t *testing.T) {
	t.Parallel()
	var a ETypeInfo
	b, err := hex.DecodeString(testdata.MarshaledKRB5etype_infoNoInfo)
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", "MarshaledKRB5etype_infoNoInfo", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", "MarshaledKRB5etype_infoNoInfo", err)
	}
	assert.Equal(t, 0, len(a), "Number of EType info entries not as expected")
}

func TestUnmarshalETypeInfo2(t *testing.T) {
	t.Parallel()
	var a ETypeInfo2
	b, err := hex.DecodeString(testdata.MarshaledKRB5etype_info2)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, 3, len(a), "Number of EType info2 entries not as expected")
	assert.Equal(t, int32(0), a[0].EType, "Etype of first etype info2 entry not as expected")
	assert.Equal(t, "Morton's #0", a[0].Salt, "Salt of first etype info2 entry not as expected")
	assert.Equal(t, []byte("s2k: 0"), a[0].S2KParams, "String to key params of first etype info2 entry not as expected")
	assert.Equal(t, int32(1), a[1].EType, "Etype of second etype info2 entry not as expected")
	assert.Equal(t, 0, len(a[1].Salt), "Salt of second etype info2 entry not as expected")
	assert.Equal(t, []byte("s2k: 1"), a[1].S2KParams, "String to key params of second etype info2 entry not as expected")
	assert.Equal(t, int32(2), a[2].EType, "Etype of third etype info2 entry not as expected")
	assert.Equal(t, "Morton's #2", a[2].Salt, "Salt of third etype info2 entry not as expected")
	assert.Equal(t, []byte("s2k: 2"), a[2].S2KParams, "String to key params of third etype info2 entry not as expected")
}

func TestUnmarshalETypeInfo2_only1(t *testing.T) {
	t.Parallel()
	var a ETypeInfo2
	b, err := hex.DecodeString(testdata.MarshaledKRB5etype_info2Only1)
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", "MarshaledKRB5etype_info2Only1", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", "MarshaledKRB5etype_info2Only1", err)
	}
	assert.Equal(t, 1, len(a), "Number of EType info2 entries not as expected")
	assert.Equal(t, int32(0), a[0].EType, "Etype of first etype info2 entry not as expected")
	assert.Equal(t, "Morton's #0", a[0].Salt, "Salt of first etype info2 entry not as expected")
	assert.Equal(t, []byte("s2k: 0"), a[0].S2KParams, "String to key params of first etype info2 entry not as expected")
}
