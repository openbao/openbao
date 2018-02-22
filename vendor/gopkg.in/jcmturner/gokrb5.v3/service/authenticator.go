package service

import (
	"encoding/base64"
	"errors"
	"fmt"
	goidentity "gopkg.in/jcmturner/goidentity.v1"
	"gopkg.in/jcmturner/gokrb5.v3/client"
	"gopkg.in/jcmturner/gokrb5.v3/config"
	"gopkg.in/jcmturner/gokrb5.v3/credentials"
	"gopkg.in/jcmturner/gokrb5.v3/gssapi"
	"gopkg.in/jcmturner/gokrb5.v3/keytab"
	"strings"
	"time"
)

// SPNEGOAuthenticator implements gopkg.in/jcmturner/goidentity.v1.Authenticator interface
type SPNEGOAuthenticator struct {
	SPNEGOHeaderValue string
	Keytab            *keytab.Keytab
	ServiceAccount    string
	ClientAddr        string
}

// Authenticate and retrieve a goidentity.Identity. In this case it is a pointer to a credentials.Credentials
func (a SPNEGOAuthenticator) Authenticate() (i goidentity.Identity, ok bool, err error) {
	b, err := base64.StdEncoding.DecodeString(a.SPNEGOHeaderValue)
	if err != nil {
		err = fmt.Errorf("SPNEGO error in base64 decoding negotiation header: %v", err)
		return
	}
	var spnego gssapi.SPNEGO
	err = spnego.Unmarshal(b)
	if !spnego.Init {
		err = fmt.Errorf("SPNEGO negotiation token is not a NegTokenInit: %v", err)
		return
	}
	if !spnego.NegTokenInit.MechTypes[0].Equal(gssapi.MechTypeOIDKRB5) {
		err = errors.New("SPNEGO OID of MechToken is not of type KRB5")
		return
	}
	var mt gssapi.MechToken
	err = mt.Unmarshal(spnego.NegTokenInit.MechToken)
	if err != nil {
		err = fmt.Errorf("SPNEGO error unmarshaling MechToken: %v", err)
		return
	}
	if !mt.IsAPReq() {
		err = errors.New("MechToken does not contain an AP_REQ - KRB_AP_ERR_MSG_TYPE")
		return
	}

	ok, c, err := ValidateAPREQ(mt.APReq, *a.Keytab, a.ServiceAccount, a.ClientAddr)
	if err != nil {
		err = fmt.Errorf("SPNEGO validation error: %v", err)
		return
	}
	i = &c
	return
}

// Mechanism returns the authentication mechanism.
func (a SPNEGOAuthenticator) Mechanism() string {
	return "SPNEGO Kerberos"
}

// KRB5BasicAuthenticator implements gopkg.in/jcmturner/goidentity.v1.Authenticator interface.
// It takes username and password so can be used for basic authentication.
type KRB5BasicAuthenticator struct {
	BasicHeaderValue string
	realm            string
	username         string
	password         string
	ServiceKeytab    *keytab.Keytab
	ServiceAccount   string
	Config           *config.Config
	SPN              string
}

// Authenticate and return the identity. The boolean indicates if the authentication was successful.
func (a KRB5BasicAuthenticator) Authenticate() (i goidentity.Identity, ok bool, err error) {
	a.realm, a.username, a.password, err = parseBasicHeaderValue(a.BasicHeaderValue)
	if err != nil {
		err = fmt.Errorf("could not parse basic authentication header: %v", err)
		return
	}
	cl := client.NewClientWithPassword(a.username, a.realm, a.password)
	cl.WithConfig(a.Config)
	err = cl.Login()
	if err != nil {
		// Username and/or password could be wrong
		err = fmt.Errorf("Error with user credentials during login: %v", err)
		return
	}
	tkt, _, err := cl.GetServiceTicket(a.SPN)
	if err != nil {
		err = fmt.Errorf("Could not get service ticket: %v", err)
		return
	}
	err = tkt.DecryptEncPart(*a.ServiceKeytab, a.ServiceAccount)
	if err != nil {
		err = fmt.Errorf("Could not decrypt service ticket: %v", err)
		return
	}
	cl.Credentials.SetAuthTime(time.Now().UTC())
	cl.Credentials.SetAuthenticated(true)
	isPAC, pac, err := tkt.GetPACType(*a.ServiceKeytab, a.ServiceAccount)
	if isPAC && err != nil {
		err = fmt.Errorf("Error processing PAC: %v", err)
		return
	}
	if isPAC {
		// There is a valid PAC. Adding attributes to creds
		cl.Credentials.SetADCredentials(credentials.ADCredentials{
			GroupMembershipSIDs: pac.KerbValidationInfo.GetGroupMembershipSIDs(),
			LogOnTime:           pac.KerbValidationInfo.LogOnTime.Time(),
			LogOffTime:          pac.KerbValidationInfo.LogOffTime.Time(),
			PasswordLastSet:     pac.KerbValidationInfo.PasswordLastSet.Time(),
			EffectiveName:       pac.KerbValidationInfo.EffectiveName.Value,
			FullName:            pac.KerbValidationInfo.FullName.Value,
			UserID:              int(pac.KerbValidationInfo.UserID),
			PrimaryGroupID:      int(pac.KerbValidationInfo.PrimaryGroupID),
			LogonServer:         pac.KerbValidationInfo.LogonServer.Value,
			LogonDomainName:     pac.KerbValidationInfo.LogonDomainName.Value,
			LogonDomainID:       pac.KerbValidationInfo.LogonDomainID.ToString(),
		})
	}
	ok = true
	i = cl.Credentials
	return
}

// Mechanism returns the authentication mechanism.
func (a KRB5BasicAuthenticator) Mechanism() string {
	return "Kerberos Basic"
}

func parseBasicHeaderValue(s string) (domain, username, password string, err error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return
	}
	v := string(b)
	vc := strings.SplitN(v, ":", 2)
	password = vc[1]
	// Domain and username can be specified in 2 formats:
	// <Username> - no domain specified
	// <Domain>\<Username>
	// <Username>@<Domain>
	if strings.Contains(vc[0], `\`) {
		u := strings.SplitN(vc[0], `\`, 2)
		domain = u[0]
		username = u[1]
	} else if strings.Contains(vc[0], `@`) {
		u := strings.SplitN(vc[0], `@`, 2)
		domain = u[1]
		username = u[0]
	} else {
		username = vc[0]
	}
	return
}
