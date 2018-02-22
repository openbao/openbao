package client

import (
	"fmt"
	"sync"
	"time"

	"gopkg.in/jcmturner/gokrb5.v3/iana/nametype"
	"gopkg.in/jcmturner/gokrb5.v3/krberror"
	"gopkg.in/jcmturner/gokrb5.v3/messages"
	"gopkg.in/jcmturner/gokrb5.v3/types"
)

// Sessions keyed on the realm name
type sessions struct {
	Entries map[string]*session
	mux     sync.RWMutex
}

// Client session struct.
type session struct {
	Realm                string
	AuthTime             time.Time
	EndTime              time.Time
	RenewTill            time.Time
	TGT                  messages.Ticket
	SessionKey           types.EncryptionKey
	SessionKeyExpiration time.Time
}

// AddSession adds a session for a realm with a TGT to the client's session cache.
// A goroutine is started to automatically renew the TGT before expiry.
func (cl *Client) AddSession(tkt messages.Ticket, dep messages.EncKDCRepPart) {
	cl.sessions.mux.Lock()
	defer cl.sessions.mux.Unlock()
	s := &session{
		Realm:                tkt.SName.NameString[1],
		AuthTime:             dep.AuthTime,
		EndTime:              dep.EndTime,
		RenewTill:            dep.RenewTill,
		TGT:                  tkt,
		SessionKey:           dep.Key,
		SessionKeyExpiration: dep.KeyExpiration,
	}
	cl.sessions.Entries[tkt.SName.NameString[1]] = s
	cl.enableAutoSessionRenewal(s)
}

// EnableAutoSessionRenewal turns on the automatic renewal for the client's TGT session.
func (cl *Client) enableAutoSessionRenewal(s *session) {
	// TODO look into using a context here
	go func(s *session) {
		for {
			//Wait until one minute before endtime
			w := (s.EndTime.Sub(time.Now().UTC()) * 5) / 6
			if w < 0 {
				return
			}
			time.Sleep(w)
			cl.updateSession(s)
		}
	}(s)
}

// RenewTGT renews the client's TGT session.
func (cl *Client) renewTGT(s *session) error {
	spn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", s.Realm},
	}
	_, tgsRep, err := cl.TGSExchange(spn, s.TGT.Realm, s.TGT, s.SessionKey, true, 0)
	if err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError, "Error renewing TGT")
	}
	s.AuthTime = tgsRep.DecryptedEncPart.AuthTime
	s.AuthTime = tgsRep.DecryptedEncPart.AuthTime
	s.EndTime = tgsRep.DecryptedEncPart.EndTime
	s.RenewTill = tgsRep.DecryptedEncPart.RenewTill
	s.TGT = tgsRep.Ticket
	s.SessionKey = tgsRep.DecryptedEncPart.Key
	s.SessionKeyExpiration = tgsRep.DecryptedEncPart.KeyExpiration
	return nil
}

func (cl *Client) updateSession(s *session) error {
	if time.Now().UTC().Before(s.RenewTill) {
		err := cl.renewTGT(s)
		if err != nil {
			return err
		}
	} else {
		err := cl.ASExchange(s.Realm, 0)
		if err != nil {
			return err
		}
	}
	return nil
}

func (cl *Client) getSessionFromRemoteRealm(realm string) (*session, error) {
	cl.sessions.mux.RLock()
	sess, ok := cl.sessions.Entries[cl.Credentials.Realm]
	cl.sessions.mux.RUnlock()
	if !ok {
		return nil, fmt.Errorf("client does not have a session for realm %s, login first", cl.Credentials.Realm)
	}

	spn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", realm},
	}

	_, tgsRep, err := cl.TGSExchange(spn, cl.Credentials.Realm, sess.TGT, sess.SessionKey, false, 0)
	if err != nil {
		return nil, err
	}
	cl.AddSession(tgsRep.Ticket, tgsRep.DecryptedEncPart)

	cl.sessions.mux.RLock()
	defer cl.sessions.mux.RUnlock()
	return cl.sessions.Entries[realm], nil
}

// GetSessionFromRealm returns the session for the realm provided.
func (cl *Client) GetSessionFromRealm(realm string) (*session, error) {
	cl.sessions.mux.RLock()
	sess, ok := cl.sessions.Entries[realm]
	cl.sessions.mux.RUnlock()
	if !ok {
		// Try to request TGT from trusted remote Realm
		return cl.getSessionFromRemoteRealm(realm)
	}
	return sess, nil
}

// GetSessionFromPrincipalName returns the session for the realm of the principal provided.
func (cl *Client) GetSessionFromPrincipalName(spn types.PrincipalName) (*session, error) {
	realm := cl.Config.ResolveRealm(spn.NameString[1])
	return cl.GetSessionFromRealm(realm)
}
