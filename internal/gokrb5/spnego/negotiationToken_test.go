package spnego

import (
	"encoding/hex"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/assert"
)

const (
	testNegTokenInit = "a08202aa308202a6a027302506092a864886f71201020206052b0501050206092a864882f71201020206062b0601050205a2820279048202756082027106092a864886f71201020201006e8202603082025ca003020105a10302010ea20703050000000000a38201706182016c30820168a003020105a10d1b0b544553542e474f4b524235a2233021a003020103a11a30181b04485454501b10686f73742e746573742e676f6b726235a382012b30820127a003020112a103020102a282011904820115d4bd890abc456f44e2e7a2e8111bd6767abf03266dfcda97c629af2ece450a5ae1f145e4a4d1bc2c848e66a6c6b31d9740b26b03cdbd2570bfcf126e90adf5f5ebce9e283ff5086da47b129b14fc0aabd4d1df9c1f3c72b80cc614dfc28783450b2c7b7749651f432b47aaa2ff158c0066b757f3fb00dd7b4f63d68276c76373ecdd3f19c66ebc43a81e577f3c263b878356f57e8d6c4eccd587b81538e70392cf7e73fc12a6f7c537a894a7bb5566c83ac4d69757aa320a51d8d690017aebf952add1889adfc3307b0e6cd8c9b57cf8589fbe52800acb6461c25473d49faa1bdceb8bce3f61db23f9cd6a09d5adceb411e1c4546b30b33331e570fd6bc50aa403557e75f488e759750ea038aab6454667d9b64f41a481d23081cfa003020112a281c70481c4d67ba2ae4cf5d917caab1d863605249320e90482563662ed92408a543b6ad5edeb8f9375e9060a205491df082fd2a5fec93dfb76f41012bb60cae20f07adbb77a1aa56f0521f36e1ea10dc9fb762902b254dd7664d0bcc6f751f2003e41990af1b4330d10477bfad638b9f0b704ac80cc47731f8ec8d801762bad8884b8de90adb1dbe7fc7b0ffafd38fb5eb8b6547cee30d89873281ce63ad70042a13478b1a7c2bdde0f223ace62dbb84e2d06f1070f4265f66e0544449335e2fcc4d0aee5bf81c5999"
	testNegTokenResp = "a1143012a0030a0100a10b06092a864886f712010202"
)

func TestUnmarshal_negTokenInit(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(testNegTokenInit)
	if err != nil {
		t.Fatalf("Error converting hex string test data to bytes: %v", err)
	}
	isInit, nt, err := UnmarshalNegToken(b)
	if err != nil {
		t.Fatalf("Error unmarshalling negotiation token: %v", err)
	}
	assert.IsType(t, NegTokenInit{}, nt, "Not the expected type NegTokenInit")
	assert.True(t, isInit, "Boolean indicating type is negTokenInit is not true")
	nInit := nt.(NegTokenInit)
	assert.Equal(t, 4, len(nInit.MechTypes))
	expectMechTypes := []asn1.ObjectIdentifier{
		[]int{1, 2, 840, 113554, 1, 2, 2},
		[]int{1, 3, 5, 1, 5, 2},
		[]int{1, 2, 840, 48018, 1, 2, 2},
		[]int{1, 3, 6, 1, 5, 2, 5},
	}
	assert.Equal(t, expectMechTypes, nInit.MechTypes, "MechTypes list in NegTokenInit not as expected")
}

func TestMarshal_negTokenInit(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(testNegTokenInit)
	if err != nil {
		t.Fatalf("Error converting hex string test data to bytes: %v", err)
	}
	_, nt, err := UnmarshalNegToken(b)
	if err != nil {
		t.Fatalf("Error unmarshalling negotiation token: %v", err)
	}
	nInit := nt.(NegTokenInit)
	mb, err := nInit.Marshal()
	if err != nil {
		t.Fatalf("Error marshalling negotiation init token: %v", err)
	}
	assert.Equal(t, b, mb, "Marshalled bytes not as expected for NegTokenInit")
}

func TestUnmarshal_negTokenResp(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(testNegTokenResp)
	if err != nil {
		t.Fatalf("Error converting hex string test data to bytes: %v", err)
	}
	isInit, nt, err := UnmarshalNegToken(b)
	if err != nil {
		t.Fatalf("Error unmarshalling negotiation token: %v", err)
	}
	assert.IsType(t, NegTokenResp{}, nt, "Not the expected type NegTokenResp")
	assert.False(t, isInit, "Boolean indicating type is negTokenInit is not false")
	nResp := nt.(NegTokenResp)
	assert.Equal(t, asn1.Enumerated(0), nResp.NegState)
	assert.Equal(t, asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}, nResp.SupportedMech, "SupportedMech type not as expected.")
}

func TestMarshal_negTokenResp(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(testNegTokenResp)
	if err != nil {
		t.Fatalf("Error converting hex string test data to bytes: %v", err)
	}
	_, nt, err := UnmarshalNegToken(b)
	if err != nil {
		t.Fatalf("Error unmarshalling negotiation token: %v", err)
	}
	nResp := nt.(NegTokenResp)
	mb, err := nResp.Marshal()
	if err != nil {
		t.Fatalf("Error marshalling negotiation init token: %v", err)
	}
	assert.Equal(t, b, mb, "Marshalled bytes not as expected for NegTokenResp")
}
