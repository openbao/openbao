package gssapi

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v5/iana/keyusage"
	"gopkg.in/jcmturner/gokrb5.v5/types"
)

const (
	// What a kerberized server might send
	testChallengeFromAcceptor = "050401ff000c000000000000575e85d601010000853b728d5268525a1386c19f"
	// What an initiator client could reply
	testChallengeReplyFromInitiator = "050400ff000c000000000000000000000101000079a033510b6f127212242b97"
	// session key used to sign the tokens above
	sessionKey     = "14f9bde6b50ec508201a97f74c4e5bd3"
	sessionKeyType = 17

	acceptorSeal  = keyusage.GSSAPI_ACCEPTOR_SEAL
	initiatorSeal = keyusage.GSSAPI_INITIATOR_SEAL
)

func getSessionKey() types.EncryptionKey {
	key, _ := hex.DecodeString(sessionKey)
	return types.EncryptionKey{
		KeyType:  sessionKeyType,
		KeyValue: key,
	}
}

func getChallengeReference() *WrapToken {
	challenge, _ := hex.DecodeString(testChallengeFromAcceptor)
	return &WrapToken{
		Flags:     0x01,
		EC:        12,
		RRC:       0,
		SndSeqNum: binary.BigEndian.Uint64(challenge[8:16]),
		Payload:   []byte{0x01, 0x01, 0x00, 0x00},
		CheckSum:  challenge[20:32],
	}
}

func getChallengeReferenceNoChksum() *WrapToken {
	c := getChallengeReference()
	c.CheckSum = nil
	return c
}

func getResponseReference() *WrapToken {
	response, _ := hex.DecodeString(testChallengeReplyFromInitiator)
	return &WrapToken{
		Flags:     0x00,
		EC:        12,
		RRC:       0,
		SndSeqNum: 0,
		Payload:   []byte{0x01, 0x01, 0x00, 0x00},
		CheckSum:  response[20:32],
	}
}

func getResponseReferenceNoChkSum() *WrapToken {
	r := getResponseReference()
	r.CheckSum = nil
	return r
}

func TestUnmarshal_Challenge(t *testing.T) {
	t.Parallel()
	challenge, _ := hex.DecodeString(testChallengeFromAcceptor)
	var wt WrapToken
	err := wt.Unmarshal(challenge, true)
	assert.Nil(t, err, "Unexpected error occurred.")
	assert.Equal(t, getChallengeReference(), &wt, "Token not decoded as expected.")
}

func TestUnmarshalFailure_Challenge(t *testing.T) {
	t.Parallel()
	challenge, _ := hex.DecodeString(testChallengeFromAcceptor)
	var wt WrapToken
	err := wt.Unmarshal(challenge, false)
	assert.NotNil(t, err, "Expected error did not occur: a message from the acceptor cannot be expected to be sent from the initiator.")
	assert.Nil(t, wt.Payload, "Token fields should not have been initialised")
	assert.Nil(t, wt.CheckSum, "Token fields should not have been initialised")
	assert.Equal(t, byte(0x00), wt.Flags, "Token fields should not have been initialised")
	assert.Equal(t, uint16(0), wt.EC, "Token fields should not have been initialised")
	assert.Equal(t, uint16(0), wt.RRC, "Token fields should not have been initialised")
	assert.Equal(t, uint64(0), wt.SndSeqNum, "Token fields should not have been initialised")
}

func TestUnmarshal_ChallengeReply(t *testing.T) {
	t.Parallel()
	response, _ := hex.DecodeString(testChallengeReplyFromInitiator)
	var wt WrapToken
	err := wt.Unmarshal(response, false)
	assert.Nil(t, err, "Unexpected error occurred.")
	assert.Equal(t, getResponseReference(), &wt, "Token not decoded as expected.")
}

func TestUnmarshalFailure_ChallengeReply(t *testing.T) {
	t.Parallel()
	response, _ := hex.DecodeString(testChallengeReplyFromInitiator)
	var wt WrapToken
	err := wt.Unmarshal(response, true)
	assert.NotNil(t, err, "Expected error did not occur: a message from the initiator cannot be expected to be sent from the acceptor.")
	assert.Nil(t, wt.Payload, "Token fields should not have been initialised")
	assert.Nil(t, wt.CheckSum, "Token fields should not have been initialised")
	assert.Equal(t, byte(0x00), wt.Flags, "Token fields should not have been initialised")
	assert.Equal(t, uint16(0), wt.EC, "Token fields should not have been initialised")
	assert.Equal(t, uint16(0), wt.RRC, "Token fields should not have been initialised")
	assert.Equal(t, uint64(0), wt.SndSeqNum, "Token fields should not have been initialised")
}

func TestChallengeChecksumVerification(t *testing.T) {
	t.Parallel()
	challenge, _ := hex.DecodeString(testChallengeFromAcceptor)
	var wt WrapToken
	wt.Unmarshal(challenge, true)
	challengeOk, cErr := wt.VerifyCheckSum(getSessionKey(), acceptorSeal)
	assert.Nil(t, cErr, "Error occurred during checksum verification.")
	assert.True(t, challengeOk, "Checksum verification failed.")
}

func TestResponseChecksumVerification(t *testing.T) {
	t.Parallel()
	reply, _ := hex.DecodeString(testChallengeReplyFromInitiator)
	var wt WrapToken
	wt.Unmarshal(reply, false)
	replyOk, rErr := wt.VerifyCheckSum(getSessionKey(), initiatorSeal)
	assert.Nil(t, rErr, "Error occurred during checksum verification.")
	assert.True(t, replyOk, "Checksum verification failed.")
}

func TestChecksumVerificationFailure(t *testing.T) {
	t.Parallel()
	challenge, _ := hex.DecodeString(testChallengeFromAcceptor)
	var wt WrapToken
	wt.Unmarshal(challenge, true)

	// Test a failure with the correct key but wrong keyusage:
	challengeOk, cErr := wt.VerifyCheckSum(getSessionKey(), initiatorSeal)
	assert.NotNil(t, cErr, "Expected error did not occur.")
	assert.False(t, challengeOk, "Checksum verification succeeded when it should have failed.")

	wrongKeyVal, _ := hex.DecodeString("14f9bde6b50ec508201a97f74c4effff")
	badKey := types.EncryptionKey{
		KeyType:  sessionKeyType,
		KeyValue: wrongKeyVal,
	}
	// Test a failure with the wrong key but correct keyusage:
	wrongKeyOk, wkErr := wt.VerifyCheckSum(badKey, acceptorSeal)
	assert.NotNil(t, wkErr, "Expected error did not occur.")
	assert.False(t, wrongKeyOk, "Checksum verification succeeded when it should have failed.")
}

func TestMarshal_Challenge(t *testing.T) {
	t.Parallel()
	bytes, _ := getChallengeReference().Marshal()
	assert.Equal(t, testChallengeFromAcceptor, hex.EncodeToString(bytes),
		"Marshalling did not yield the expected result.")
}

func TestMarshal_ChallengeReply(t *testing.T) {
	t.Parallel()
	bytes, _ := getResponseReference().Marshal()
	assert.Equal(t, testChallengeReplyFromInitiator, hex.EncodeToString(bytes),
		"Marshalling did not yield the expected result.")
}

func TestMarshal_Failures(t *testing.T) {
	t.Parallel()
	noChkSum := getResponseReferenceNoChkSum()
	chkBytes, chkErr := noChkSum.Marshal()
	assert.Nil(t, chkBytes, "No bytes should be returned.")
	assert.NotNil(t, chkErr, "Expected an error as no checksum was set")

	noPayload := getResponseReference()
	noPayload.Payload = nil
	pldBytes, pldErr := noPayload.Marshal()
	assert.Nil(t, pldBytes, "No bytes should be returned.")
	assert.NotNil(t, pldErr, "Expected an error as no checksum was set")
}

func TestNewInitiatorTokenSignatureAndMarshalling(t *testing.T) {
	t.Parallel()
	token, tErr := NewInitiatorToken([]byte{0x01, 0x01, 0x00, 0x00}, getSessionKey())
	assert.Nil(t, tErr, "Unexepected error.")
	assert.Equal(t, getResponseReference(), token, "Token failed to be marshalled to the expected bytes.")
}
