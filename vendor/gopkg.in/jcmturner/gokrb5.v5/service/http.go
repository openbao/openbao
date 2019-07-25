package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"

	"gopkg.in/jcmturner/gokrb5.v5/gssapi"
	"gopkg.in/jcmturner/gokrb5.v5/keytab"
)

// POTENTIAL BREAKING CHANGE notice. Context keys used will change to a name-spaced strings to avoid clashes.
// If you are using the constants service.CTXKeyAuthenticated and service.CTXKeyCredentials
// defined below when retrieving data from the request context your code will be unaffected.
// However if, for example, you are retrieving context like this: r.Context().Value(1) then
// you will need to update to replace the 1 with service.CTXKeyCredentials.
type ctxKey int

const (
	// spnegoNegTokenRespKRBAcceptCompleted - The response on successful authentication always has this header. Capturing as const so we don't have marshaling and encoding overhead.
	spnegoNegTokenRespKRBAcceptCompleted = "Negotiate oRQwEqADCgEAoQsGCSqGSIb3EgECAg=="
	// spnegoNegTokenRespReject - The response on a failed authentication always has this rejection header. Capturing as const so we don't have marshaling and encoding overhead.
	spnegoNegTokenRespReject = "Negotiate oQcwBaADCgEC"
	// CTXKeyAuthenticated is the request context key holding a boolean indicating if the request has been authenticated.
	CTXKeyAuthenticated ctxKey = 0
	// CTXKeyCredentials is the request context key holding the credentials gopkg.in/jcmturner/goidentity.v2/Identity object.
	CTXKeyCredentials ctxKey = 1
	// HTTPHeaderAuthRequest is the header that will hold authn/z information.
	HTTPHeaderAuthRequest = "Authorization"
	// HTTPHeaderAuthResponse is the header that will hold SPNEGO data from the server.
	HTTPHeaderAuthResponse = "WWW-Authenticate"
	// HTTPHeaderAuthResponseValueKey is the key in the auth header for SPNEGO.
	HTTPHeaderAuthResponseValueKey = "Negotiate"
	// UnauthorizedMsg is the message returned in the body when authentication fails.
	UnauthorizedMsg = "Unauthorised.\n"
)

// SPNEGOKRB5Authenticate is a Kerberos SPNEGO authentication HTTP handler wrapper.
//
// kt - keytab for the service user
//
// ktprinc - keytab principal override for the service.
// The service looks for this principal in the keytab to use to decrypt tickets.
// If "" is passed as ktprinc then the principal will be automatically derived
// from the service name (SName) and realm in the ticket the service is trying to decrypt.
// This is often sufficient if you create the SPN in MIT KDC with: /usr/sbin/kadmin.local -q "add_principal HTTP/<fqdn>"
// When Active Directory is used for the KDC this may need to be the account name you have set the SPN against
// (setspn.exe -a "HTTP/<fqdn>" <account name>)
// If you are unsure run:
//
// klist -k <service's keytab file>
//
// and use the value from the Principal column for the keytab entry the service should use.
func SPNEGOKRB5Authenticate(f http.Handler, kt keytab.Keytab, ktprinc string, requireHostAddr bool, l *log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := strings.SplitN(r.Header.Get(HTTPHeaderAuthRequest), " ", 2)
		if len(s) != 2 || s[0] != HTTPHeaderAuthResponseValueKey {
			w.Header().Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
			w.WriteHeader(401)
			w.Write([]byte(UnauthorizedMsg))
			return
		}
		b, err := base64.StdEncoding.DecodeString(s[1])
		if err != nil {
			rejectSPNEGO(w, l, fmt.Sprintf("%v - SPNEGO error in base64 decoding negotiation header: %v", r.RemoteAddr, err))
			return
		}
		var spnego gssapi.SPNEGO
		err = spnego.Unmarshal(b)
		if !spnego.Init {
			rejectSPNEGO(w, l, fmt.Sprintf("%v - SPNEGO negotiation token is not a NegTokenInit: %v", r.RemoteAddr, err))
			return
		}
		if !spnego.NegTokenInit.MechTypes[0].Equal(gssapi.MechTypeOIDKRB5) && !spnego.NegTokenInit.MechTypes[0].Equal(gssapi.MechTypeOIDMSLegacyKRB5) {
			rejectSPNEGO(w, l, fmt.Sprintf("%v - SPNEGO OID of MechToken is not of type KRB5", r.RemoteAddr))
			return
		}
		var mt gssapi.MechToken
		err = mt.Unmarshal(spnego.NegTokenInit.MechToken)
		if err != nil {
			rejectSPNEGO(w, l, fmt.Sprintf("%v - SPNEGO error unmarshaling MechToken: %v", r.RemoteAddr, err))
			return
		}
		if !mt.IsAPReq() {
			rejectSPNEGO(w, l, fmt.Sprintf("%v - MechToken does not contain an AP_REQ - KRB_AP_ERR_MSG_TYPE", r.RemoteAddr))
			return
		}

		if ok, creds, err := ValidateAPREQ(mt.APReq, kt, ktprinc, r.RemoteAddr, requireHostAddr); ok {
			ctx := r.Context()
			ctx = context.WithValue(ctx, CTXKeyCredentials, creds)
			ctx = context.WithValue(ctx, CTXKeyAuthenticated, true)
			if l != nil {
				l.Printf("%v %s@%s - SPNEGO authentication succeeded", r.RemoteAddr, creds.Username, creds.Realm)
			}
			spnegoResponseAcceptCompleted(w)
			f.ServeHTTP(w, r.WithContext(ctx))
		} else {
			rejectSPNEGO(w, l, fmt.Sprintf("%v - SPNEGO Kerberos authentication failed: %v", r.RemoteAddr, err))
			return
		}
	})
}

// Set the headers for a rejected SPNEGO negotiation and return an unauthorized status code.
func rejectSPNEGO(w http.ResponseWriter, l *log.Logger, logMsg string) {
	if l != nil {
		l.Println(logMsg)
	}
	spnegoResponseReject(w)
}

func spnegoResponseReject(w http.ResponseWriter) {
	w.Header().Set(HTTPHeaderAuthResponse, spnegoNegTokenRespReject)
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(UnauthorizedMsg))
}

func spnegoResponseAcceptCompleted(w http.ResponseWriter) {
	w.Header().Set(HTTPHeaderAuthResponse, spnegoNegTokenRespKRBAcceptCompleted)
}
