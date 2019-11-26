package pac

import (
	"encoding/hex"
	"testing"

	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/test/testdata"
	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/rpc.v1/mstypes"
)

const (
	ClaimsEntryIDStr            = "ad://ext/sAMAccountName:88d5d9085ea5c0c0"
	ClaimsEntryValueStr         = "testuser1"
	ClaimsEntryIDInt64          = "ad://ext/msDS-SupportedE:88d5dea8f1af5f19"
	ClaimsEntryValueInt64 int64 = 28
	ClaimsEntryIDUInt64         = "ad://ext/objectClass:88d5de791e7b27e6"
)

func TestPAC_ClientClaimsInfoStr_Unmarshal(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(testdata.MarshaledPAC_ClientClaimsInfoStr)
	if err != nil {
		t.Fatal("Could not decode test data hex string")
	}
	var k ClientClaimsInfo
	err = k.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshaling test data: %v", err)
	}
	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrayCount, "claims array count not as expected")
	assert.Equal(t, mstypes.ClaimsSourceTypeAD, k.ClaimsSet.ClaimsArrays[0].ClaimsSourceType, "claims source type not as expected")
	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrays[0].ClaimsCount, "claims count not as expected")
	assert.Equal(t, uint16(3), k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].Type, "claims entry type not as expected")
	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].TypeString.ValueCount, "claims value count not as expected")
	assert.Equal(t, ClaimsEntryIDStr, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].ID, "claims entry ID not as expected")
	assert.Equal(t, []mstypes.LPWSTR{{Value: ClaimsEntryValueStr}}, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].TypeString.Value, "claims value not as expected")
	assert.Equal(t, mstypes.CompressionFormatNone, k.ClaimsSetMetadata.CompressionFormat, "compression format not as expected")
}

func TestPAC_ClientClaimsMultiValueUint_Unmarshal(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(testdata.MarshaledPAC_ClientClaimsInfoMultiUint)
	if err != nil {
		t.Fatal("Could not decode test data hex string")
	}
	var k ClientClaimsInfo
	err = k.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshaling test data: %v", err)
	}
	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrayCount, "claims array count not as expected")
	assert.Equal(t, mstypes.ClaimsSourceTypeAD, k.ClaimsSet.ClaimsArrays[0].ClaimsSourceType, "claims source type not as expected")
	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrays[0].ClaimsCount, "claims count not as expected")
	assert.Equal(t, mstypes.ClaimTypeIDUInt64, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].Type, "claims entry type not as expected")
	assert.Equal(t, uint32(4), k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].TypeUInt64.ValueCount, "claims value count not as expected")
	assert.Equal(t, ClaimsEntryIDUInt64, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].ID, "claims entry ID not as expected")
	assert.Equal(t, []uint64{655369, 65543, 65542, 65536}, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].TypeUInt64.Value, "claims value not as expected")
	assert.Equal(t, mstypes.CompressionFormatNone, k.ClaimsSetMetadata.CompressionFormat, "compression format not as expected")
}

func TestPAC_ClientClaimsInt_Unmarshal(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(testdata.MarshaledPAC_ClientClaimsInfoInt)
	if err != nil {
		t.Fatal("Could not decode test data hex string")
	}
	var k ClientClaimsInfo
	err = k.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshaling test data: %v", err)
	}
	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrayCount, "claims array count not as expected")
	assert.Equal(t, mstypes.ClaimsSourceTypeAD, k.ClaimsSet.ClaimsArrays[0].ClaimsSourceType, "claims source type not as expected")
	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrays[0].ClaimsCount, "claims count not as expected")
	assert.Equal(t, mstypes.ClaimTypeIDInt64, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].Type, "claims entry type not as expected")
	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].TypeInt64.ValueCount, "claims value count not as expected")
	assert.Equal(t, ClaimsEntryIDInt64, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].ID, "claims entry ID not as expected")
	assert.Equal(t, []int64{ClaimsEntryValueInt64}, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].TypeInt64.Value, "claims value not as expected")
	assert.Equal(t, mstypes.CompressionFormatNone, k.ClaimsSetMetadata.CompressionFormat, "compression format not as expected")
}

func TestPAC_ClientClaimsMultiValueStr_Unmarshal(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(testdata.MarshaledPAC_ClientClaimsInfoMultiStr)
	if err != nil {
		t.Fatal("Could not decode test data hex string")
	}
	var k ClientClaimsInfo
	err = k.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshaling test data: %v", err)
	}
	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrayCount, "claims array count not as expected")
	assert.Equal(t, mstypes.ClaimsSourceTypeAD, k.ClaimsSet.ClaimsArrays[0].ClaimsSourceType, "claims source type not as expected")
	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrays[0].ClaimsCount, "claims count not as expected")
	assert.Equal(t, mstypes.ClaimTypeIDString, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].Type, "claims entry type not as expected")
	assert.Equal(t, uint32(4), k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].TypeString.ValueCount, "claims value count not as expected")
	assert.Equal(t, "ad://ext/otherIpPhone:88d5de9f6b4af985", k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].ID, "claims entry ID not as expected")
	assert.Equal(t, []mstypes.LPWSTR{{Value: "str1"}, {Value: "str2"}, {Value: "str3"}, {Value: "str4"}}, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].TypeString.Value, "claims value not as expected")
	assert.Equal(t, mstypes.CompressionFormatNone, k.ClaimsSetMetadata.CompressionFormat, "compression format not as expected")
}

func TestPAC_ClientClaimsInfoMultiEntry_Unmarshal(t *testing.T) {
	// Has an int and a str claim type
	t.Parallel()
	b, err := hex.DecodeString(testdata.MarshaledPAC_ClientClaimsInfoMulti)
	if err != nil {
		t.Fatal("Could not decode test data hex string")
	}
	var k ClientClaimsInfo
	err = k.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshaling test data: %v", err)
	}
	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrayCount, "claims array count not as expected")
	assert.Equal(t, mstypes.ClaimsSourceTypeAD, k.ClaimsSet.ClaimsArrays[0].ClaimsSourceType, "claims source type not as expected")
	assert.Equal(t, uint32(2), k.ClaimsSet.ClaimsArrays[0].ClaimsCount, "claims count not as expected")
	assert.Equal(t, uint16(1), k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].Type, "claims entry type not as expected")
	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].TypeInt64.ValueCount, "claims value count not as expected")
	assert.Equal(t, ClaimsEntryIDInt64, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].ID, "claims entry ID not as expected")
	assert.Equal(t, []int64{int64(28)}, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].TypeInt64.Value, "claims value not as expected")
	assert.Equal(t, uint16(3), k.ClaimsSet.ClaimsArrays[0].ClaimEntries[1].Type, "claims entry type not as expected")
	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrays[0].ClaimEntries[1].TypeString.ValueCount, "claims value count not as expected")
	assert.Equal(t, ClaimsEntryIDStr, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[1].ID, "claims entry ID not as expected")
	assert.Equal(t, []mstypes.LPWSTR{{Value: ClaimsEntryValueStr}}, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[1].TypeString.Value, "claims value not as expected")
	assert.Equal(t, mstypes.CompressionFormatNone, k.ClaimsSetMetadata.CompressionFormat, "compression format not as expected")
}

// Compressed claims not yet supported.
//func TestPAC_ClientClaimsInfo_Unmarshal_UnsupportedCompression(t *testing.T) {
//	t.Parallel()
//	b, err := hex.DecodeString(testdata.MarshaledPAC_ClientClaimsInfo_XPRESS_HUFF)
//	if err != nil {
//		t.Fatal("Could not decode test data hex string")
//	}
//	var k ClientClaimsInfo
//	err = k.Unmarshal(b)
//	if err != nil {
//		t.Fatalf("Error unmarshaling test data: %v", err)
//	}
//	assert.Equal(t, mstypes.CompressionFormatXPressHuff, k.ClaimsSetMetadata.CompressionFormat, "compression format not as expected")
//}
