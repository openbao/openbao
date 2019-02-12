package types

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v5/iana/patype"
	"gopkg.in/jcmturner/gokrb5.v5/testdata"
)

func TestUnmarshalPADataSequence(t *testing.T) {
	t.Parallel()
	var a PADataSequence
	v := "encode_krb5_padata_sequence"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
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
	v := "encode_krb5_padata_sequence(empty)"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, 0, len(a), "Number of PAData items in the sequence not as expected")
}

func TestUnmarshalPAEncTSEnc(t *testing.T) {
	t.Parallel()
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	var a PAEncTSEnc
	v := "encode_krb5_pa_enc_ts"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, tt, a.PATimestamp, "PA timestamp not as expected")
	assert.Equal(t, 123456, a.PAUSec, "PA microseconds not as expected")
}

func TestUnmarshalPAEncTSEnc_nousec(t *testing.T) {
	t.Parallel()
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	var a PAEncTSEnc
	v := "encode_krb5_pa_enc_ts(nousec)"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, tt, a.PATimestamp, "PA timestamp not as expected")
	assert.Equal(t, 0, a.PAUSec, "PA microseconds not as expected")
}

func TestUnmarshalETypeInfo(t *testing.T) {
	t.Parallel()
	var a ETypeInfo
	v := "encode_krb5_etype_info"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
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
	v := "encode_krb5_etype_info(only1)"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, 1, len(a), "Number of EType info entries not as expected")
	assert.Equal(t, int32(0), a[0].EType, "Etype of first etype info entry not as expected")
	assert.Equal(t, []byte("Morton's #0"), a[0].Salt, "Salt of first etype info entry not as expected")
}

func TestUnmarshalETypeInfo_noinfo(t *testing.T) {
	t.Parallel()
	var a ETypeInfo
	v := "encode_krb5_etype_info(noinfo)"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, 0, len(a), "Number of EType info entries not as expected")
}

func TestUnmarshalETypeInfo2(t *testing.T) {
	t.Parallel()
	var a ETypeInfo2
	v := "encode_krb5_etype_info2"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
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
	v := "encode_krb5_etype_info2(only1)"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, 1, len(a), "Number of EType info2 entries not as expected")
	assert.Equal(t, int32(0), a[0].EType, "Etype of first etype info2 entry not as expected")
	assert.Equal(t, "Morton's #0", a[0].Salt, "Salt of first etype info2 entry not as expected")
	assert.Equal(t, []byte("s2k: 0"), a[0].S2KParams, "String to key params of first etype info2 entry not as expected")
}
