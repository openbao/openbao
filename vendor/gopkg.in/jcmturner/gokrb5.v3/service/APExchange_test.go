package service

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v3/client"
	"gopkg.in/jcmturner/gokrb5.v3/config"
	"gopkg.in/jcmturner/gokrb5.v3/credentials"
	"gopkg.in/jcmturner/gokrb5.v3/iana/errorcode"
	"gopkg.in/jcmturner/gokrb5.v3/iana/flags"
	"gopkg.in/jcmturner/gokrb5.v3/iana/nametype"
	"gopkg.in/jcmturner/gokrb5.v3/keytab"
	"gopkg.in/jcmturner/gokrb5.v3/messages"
	"gopkg.in/jcmturner/gokrb5.v3/testdata"
	"gopkg.in/jcmturner/gokrb5.v3/types"
	"testing"
	"time"
)

func TestValidateAPREQ(t *testing.T) {
	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt, _ := keytab.Parse(b)
	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName, cl.Credentials.Realm,
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		newTestAuthenticator(*cl.Credentials),
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	ok, _, err := ValidateAPREQ(APReq, kt, "", "127.0.0.1")
	if !ok || err != nil {
		t.Fatalf("Validation of AP_REQ failed when it should not have: %v", err)
	}
}

func TestValidateAPREQ_KRB_AP_ERR_BADMATCH(t *testing.T) {
	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt, _ := keytab.Parse(b)
	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName, cl.Credentials.Realm,
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	a := newTestAuthenticator(*cl.Credentials)
	a.CName = types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"BADMATCH"},
	}
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		a,
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	ok, _, err := ValidateAPREQ(APReq, kt, "", "127.0.0.1")
	if ok || err == nil {
		t.Fatal("Validation of AP_REQ passed when it should not have")
	}
	if _, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_BADMATCH, err.(messages.KRBError).ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestValidateAPREQ_LargeClockSkew(t *testing.T) {
	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt, _ := keytab.Parse(b)
	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName, cl.Credentials.Realm,
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	a := newTestAuthenticator(*cl.Credentials)
	a.CTime = a.CTime.Add(time.Duration(-10) * time.Minute)
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		a,
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	ok, _, err := ValidateAPREQ(APReq, kt, "", "127.0.0.1")
	if ok || err == nil {
		t.Fatal("Validation of AP_REQ passed when it should not have")
	}
	if _, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_SKEW, err.(messages.KRBError).ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestValidateAPREQ_Replay(t *testing.T) {
	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt, _ := keytab.Parse(b)
	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName, cl.Credentials.Realm,
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		newTestAuthenticator(*cl.Credentials),
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	ok, _, err := ValidateAPREQ(APReq, kt, "", "127.0.0.1")
	if !ok || err != nil {
		t.Fatalf("Validation of AP_REQ failed when it should not have: %v", err)
	}
	// Replay
	ok, _, err = ValidateAPREQ(APReq, kt, "", "127.0.0.1")
	if ok || err == nil {
		t.Fatal("Validation of AP_REQ passed when it should not have")
	}
	assert.IsType(t, messages.KRBError{}, err, "Error is not a KRBError")
	assert.Equal(t, errorcode.KRB_AP_ERR_REPEAT, err.(messages.KRBError).ErrorCode, "Error code not as expected")
}

func TestValidateAPREQ_FutureTicket(t *testing.T) {
	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt, _ := keytab.Parse(b)
	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName, cl.Credentials.Realm,
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st.Add(time.Duration(60)*time.Minute),
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	a := newTestAuthenticator(*cl.Credentials)
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		a,
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	ok, _, err := ValidateAPREQ(APReq, kt, "", "127.0.0.1")
	if ok || err == nil {
		t.Fatal("Validation of AP_REQ passed when it should not have")
	}
	if _, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_TKT_NYV, err.(messages.KRBError).ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestValidateAPREQ_InvalidTicket(t *testing.T) {
	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt, _ := keytab.Parse(b)
	st := time.Now().UTC()
	f := types.NewKrbFlags()
	types.SetFlag(&f, flags.Invalid)
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName, cl.Credentials.Realm,
		sname, "TEST.GOKRB5",
		f,
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		newTestAuthenticator(*cl.Credentials),
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	ok, _, err := ValidateAPREQ(APReq, kt, "", "127.0.0.1")
	if ok || err == nil {
		t.Fatal("Validation of AP_REQ passed when it should not have")
	}
	if _, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_TKT_NYV, err.(messages.KRBError).ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestValidateAPREQ_ExpiredTicket(t *testing.T) {
	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt, _ := keytab.Parse(b)
	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName, cl.Credentials.Realm,
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(-30)*time.Minute),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	a := newTestAuthenticator(*cl.Credentials)
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		a,
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	ok, _, err := ValidateAPREQ(APReq, kt, "", "127.0.0.1")
	if ok || err == nil {
		t.Fatal("Validation of AP_REQ passed when it should not have")
	}
	if _, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_TKT_EXPIRED, err.(messages.KRBError).ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func newTestAuthenticator(creds credentials.Credentials) types.Authenticator {
	auth, _ := types.NewAuthenticator(creds.Realm, creds.CName)
	auth.GenerateSeqNumberAndSubKey(18, 32)
	//auth.Cksum = types.Checksum{
	//	CksumType: chksumtype.GSSAPI,
	//	Checksum:  newAuthenticatorChksum([]int{GSS_C_INTEG_FLAG, GSS_C_CONF_FLAG}),
	//}
	return auth
}

func getClient() client.Client {
	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	cl := client.NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)
	return cl
}
