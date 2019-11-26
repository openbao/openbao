package gssapi

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/iana/keyusage"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/types"
	"github.com/stretchr/testify/assert"
)

const (
	testMICPayload = "deadbeef"
	// What a kerberized server might send
	testMICChallengeFromAcceptor = "040401ffffffffff00000000575e85d6c34d12ba3e5b1b1310cd9cb3"
	// What an initiator client could reply
	testMICChallengeReplyFromInitiator = "040400ffffffffff00000000000000009649ca09d2f1bc51ff6e5ca3"

	acceptorSign  = keyusage.GSSAPI_ACCEPTOR_SIGN
	initiatorSign = keyusage.GSSAPI_INITIATOR_SIGN
)

func getMICChallengeReference() *MICToken {
	challenge, _ := hex.DecodeString(testMICChallengeFromAcceptor)
	return &MICToken{
		Flags:     MICTokenFlagSentByAcceptor,
		SndSeqNum: binary.BigEndian.Uint64(challenge[8:16]),
		Payload:   nil,
		Checksum:  challenge[16:],
	}
}

func getMICChallengeReferenceNoChksum() *MICToken {
	c := getMICChallengeReference()
	c.Checksum = nil
	return c
}

func getMICResponseReference() *MICToken {
	response, _ := hex.DecodeString(testMICChallengeReplyFromInitiator)
	return &MICToken{
		Flags:     0x00,
		SndSeqNum: 0,
		Payload:   nil,
		Checksum:  response[16:],
	}
}

func getMICResponseReferenceNoChkSum() *MICToken {
	r := getMICResponseReference()
	r.Checksum = nil
	return r
}

func TestUnmarshal_MICChallenge(t *testing.T) {
	t.Parallel()
	challenge, _ := hex.DecodeString(testMICChallengeFromAcceptor)
	var mt MICToken
	err := mt.Unmarshal(challenge, true)
	assert.Nil(t, err, "Unexpected error occurred.")
	assert.Equal(t, getMICChallengeReference(), &mt, "Token not decoded as expected.")
}

func TestUnmarshalFailure_MICChallenge(t *testing.T) {
	t.Parallel()
	challenge, _ := hex.DecodeString(testMICChallengeFromAcceptor)
	var mt MICToken
	err := mt.Unmarshal(challenge, false)
	assert.NotNil(t, err, "Expected error did not occur: a message from the acceptor cannot be expected to be sent from the initiator.")
	assert.Nil(t, mt.Payload, "Token fields should not have been initialised")
	assert.Nil(t, mt.Checksum, "Token fields should not have been initialised")
	assert.Equal(t, byte(0x00), mt.Flags, "Token fields should not have been initialised")
	assert.Equal(t, uint64(0), mt.SndSeqNum, "Token fields should not have been initialised")
}

func TestUnmarshal_MICChallengeReply(t *testing.T) {
	t.Parallel()
	response, _ := hex.DecodeString(testMICChallengeReplyFromInitiator)
	var mt MICToken
	err := mt.Unmarshal(response, false)
	assert.Nil(t, err, "Unexpected error occurred.")
	assert.Equal(t, getMICResponseReference(), &mt, "Token not decoded as expected.")
}

func TestUnmarshalFailure_MICChallengeReply(t *testing.T) {
	t.Parallel()
	response, _ := hex.DecodeString(testMICChallengeReplyFromInitiator)
	var mt MICToken
	err := mt.Unmarshal(response, true)
	assert.NotNil(t, err, "Expected error did not occur: a message from the initiator cannot be expected to be sent from the acceptor.")
	assert.Nil(t, mt.Payload, "Token fields should not have been initialised")
	assert.Nil(t, mt.Checksum, "Token fields should not have been initialised")
	assert.Equal(t, byte(0x00), mt.Flags, "Token fields should not have been initialised")
	assert.Equal(t, uint64(0), mt.SndSeqNum, "Token fields should not have been initialised")
}

func TestMICChallengeChecksumVerification(t *testing.T) {
	t.Parallel()
	challenge, _ := hex.DecodeString(testMICChallengeFromAcceptor)
	var mt MICToken
	mt.Unmarshal(challenge, true)
	mt.Payload, _ = hex.DecodeString(testMICPayload)
	challengeOk, cErr := mt.Verify(getSessionKey(), acceptorSign)
	assert.Nil(t, cErr, "Error occurred during checksum verification.")
	assert.True(t, challengeOk, "Checksum verification failed.")
}

func TestMICResponseChecksumVerification(t *testing.T) {
	t.Parallel()
	reply, _ := hex.DecodeString(testMICChallengeReplyFromInitiator)
	var mt MICToken
	mt.Unmarshal(reply, false)
	mt.Payload, _ = hex.DecodeString(testMICPayload)
	replyOk, rErr := mt.Verify(getSessionKey(), initiatorSign)
	assert.Nil(t, rErr, "Error occurred during checksum verification.")
	assert.True(t, replyOk, "Checksum verification failed.")
}

func TestMICChecksumVerificationFailure(t *testing.T) {
	t.Parallel()
	challenge, _ := hex.DecodeString(testMICChallengeFromAcceptor)
	var mt MICToken
	mt.Unmarshal(challenge, true)

	// Test a failure with the correct key but wrong keyusage:
	challengeOk, cErr := mt.Verify(getSessionKey(), initiatorSign)
	assert.NotNil(t, cErr, "Expected error did not occur.")
	assert.False(t, challengeOk, "Checksum verification succeeded when it should have failed.")

	wrongKeyVal, _ := hex.DecodeString("14f9bde6b50ec508201a97f74c4effff")
	badKey := types.EncryptionKey{
		KeyType:  sessionKeyType,
		KeyValue: wrongKeyVal,
	}
	// Test a failure with the wrong key but correct keyusage:
	wrongKeyOk, wkErr := mt.Verify(badKey, acceptorSign)
	assert.NotNil(t, wkErr, "Expected error did not occur.")
	assert.False(t, wrongKeyOk, "Checksum verification succeeded when it should have failed.")
}

func TestMarshal_MICChallenge(t *testing.T) {
	t.Parallel()
	bytes, _ := getMICChallengeReference().Marshal()
	assert.Equal(t, testMICChallengeFromAcceptor, hex.EncodeToString(bytes),
		"Marshalling did not yield the expected result.")
}

func TestMarshal_MICChallengeReply(t *testing.T) {
	t.Parallel()
	bytes, _ := getMICResponseReference().Marshal()
	assert.Equal(t, testMICChallengeReplyFromInitiator, hex.EncodeToString(bytes),
		"Marshalling did not yield the expected result.")
}

func TestMarshal_MICFailures(t *testing.T) {
	t.Parallel()
	noChkSum := getMICResponseReferenceNoChkSum()
	chkBytes, chkErr := noChkSum.Marshal()
	assert.Nil(t, chkBytes, "No bytes should be returned.")
	assert.NotNil(t, chkErr, "Expected an error as no checksum was set")
}

func TestNewInitiatorMICTokenSignatureAndMarshalling(t *testing.T) {
	t.Parallel()
	bytes, _ := hex.DecodeString(testMICPayload)
	token, tErr := NewInitiatorMICToken(bytes, getSessionKey())
	token.Payload = nil
	assert.Nil(t, tErr, "Unexpected error.")
	assert.Equal(t, getMICResponseReference(), token, "Token failed to be marshalled to the expected bytes.")
}
