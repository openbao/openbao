package client

import (
	"gopkg.in/jcmturner/gokrb5.v3/crypto"
	"gopkg.in/jcmturner/gokrb5.v3/crypto/etype"
	"gopkg.in/jcmturner/gokrb5.v3/iana/errorcode"
	"gopkg.in/jcmturner/gokrb5.v3/iana/keyusage"
	"gopkg.in/jcmturner/gokrb5.v3/iana/patype"
	"gopkg.in/jcmturner/gokrb5.v3/krberror"
	"gopkg.in/jcmturner/gokrb5.v3/messages"
	"gopkg.in/jcmturner/gokrb5.v3/types"
)

// ASExchange performs an AS exchange for the client to retrieve a TGT.
func (cl *Client) ASExchange(realm string, referral int) error {
	if ok, err := cl.IsConfigured(); !ok {
		return krberror.Errorf(err, krberror.ConfigError, "AS Exchange cannot be preformed")
	}
	ASReq, err := messages.NewASReq(realm, cl.Config, cl.Credentials.CName)
	if err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError, "Error generating new AS_REQ")
	}
	err = setPAData(cl, messages.KRBError{}, &ASReq)
	if err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: failed setting AS_REQ PAData")
	}
	b, err := ASReq.Marshal()
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed marshaling AS_REQ")
	}

	var ASRep messages.ASRep

	rb, err := cl.SendToKDC(b, realm)
	if err != nil {
		if e, ok := err.(messages.KRBError); ok {
			switch e.ErrorCode {
			case errorcode.KDC_ERR_PREAUTH_REQUIRED:
				// From now on assume this client will need to do this pre-auth and set the PAData
				cl.GoKrb5Conf.AssumePAEncTimestampRequired = true
				err = setPAData(cl, e, &ASReq)
				if err != nil {
					return krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: failed setting AS_REQ PAData for pre-authentication required")
				}
				b, err := ASReq.Marshal()
				if err != nil {
					return krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed marshaling AS_REQ with PAData")
				}
				rb, err = cl.SendToKDC(b, realm)
				if err != nil {
					return krberror.Errorf(err, krberror.NetworkingError, "AS Exchange Error: failed sending AS_REQ to KDC")
				}
			case errorcode.KDC_ERR_WRONG_REALM:
				// Client referral https://tools.ietf.org/html/rfc6806.html#section-7
				if referral > 5 {
					return krberror.Errorf(err, krberror.KRBMsgError, "maximum number of client referrals exceeded")
				}
				referral += 1
				return cl.ASExchange(e.CRealm, referral)
			}
		} else {
			return krberror.Errorf(err, krberror.NetworkingError, "AS Exchange Error: failed sending AS_REQ to KDC")
		}
	}
	err = ASRep.Unmarshal(rb)
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed to process the AS_REP")
	}
	if ok, err := ASRep.IsValid(cl.Config, cl.Credentials, ASReq); !ok {
		return krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: AS_REP is not valid")
	}
	cl.AddSession(ASRep.Ticket, ASRep.DecryptedEncPart)
	return nil
}

func setPAData(cl *Client, krberr messages.KRBError, ASReq *messages.ASReq) error {
	if !cl.GoKrb5Conf.DisablePAFXFast {
		pa := types.PAData{PADataType: patype.PA_REQ_ENC_PA_REP}
		ASReq.PAData = append(ASReq.PAData, pa)
	}
	if cl.GoKrb5Conf.AssumePAEncTimestampRequired {
		paTSb, err := types.GetPAEncTSEncAsnMarshalled()
		if err != nil {
			return krberror.Errorf(err, krberror.KRBMsgError, "Error creating PAEncTSEnc for Pre-Authentication")
		}
		var et etype.EType
		if krberr.ErrorCode == 0 {
			// This is not in response to an error from the KDC. It is preemptive
			et, err = crypto.GetEtype(ASReq.ReqBody.EType[0]) // Take the first as preference
			if err != nil {
				return krberror.Errorf(err, krberror.EncryptingError, "error getting etype for pre-auth encryption")
			}
		} else {
			// Get the etype to use from the PA data in the KRBError e-data
			et, err = preAuthEType(krberr)
			if err != nil {
				return krberror.Errorf(err, krberror.EncryptingError, "error getting etype for pre-auth encryption")
			}
		}
		key, err := cl.Key(et, krberr)
		if err != nil {
			return krberror.Errorf(err, krberror.EncryptingError, "Error getting key from credentials")
		}
		paEncTS, err := crypto.GetEncryptedData(paTSb, key, keyusage.AS_REQ_PA_ENC_TIMESTAMP, 1)
		if err != nil {
			return krberror.Errorf(err, krberror.EncryptingError, "Error encrypting pre-authentication timestamp")
		}
		pb, err := paEncTS.Marshal()
		if err != nil {
			return krberror.Errorf(err, krberror.EncodingError, "Error marshaling the PAEncTSEnc encrypted data")
		}
		pa := types.PAData{
			PADataType:  patype.PA_ENC_TIMESTAMP,
			PADataValue: pb,
		}
		ASReq.PAData = append(ASReq.PAData, pa)
	}
	return nil
}

func preAuthEType(krberr messages.KRBError) (etype etype.EType, err error) {
	//The preferred ordering of the "hint" pre-authentication data that
	//affect client key selection is: ETYPE-INFO2, followed by ETYPE-INFO,
	//followed by PW-SALT.
	//A KDC SHOULD NOT send PA-PW-SALT when issuing a KRB-ERROR message
	//that requests additional pre-authentication.  Implementation note:
	//Some KDC implementations issue an erroneous PA-PW-SALT when issuing a
	//KRB-ERROR message that requests additional pre-authentication.
	//Therefore, clients SHOULD ignore a PA-PW-SALT accompanying a
	//KRB-ERROR message that requests additional pre-authentication.
	var etypeID int
	var pas types.PADataSequence
	e := pas.Unmarshal(krberr.EData)
	if e != nil {
		err = krberror.Errorf(e, krberror.EncodingError, "error unmashalling KRBError data")
		return
	}
	for _, pa := range pas {
		switch pa.PADataType {
		case patype.PA_ETYPE_INFO2:
			info, e := pa.GetETypeInfo2()
			if e != nil {
				err = krberror.Errorf(e, krberror.EncodingError, "error unmashalling ETYPE-INFO2 data")
				return
			}
			etypeID = info[0].EType
			break
		case patype.PA_ETYPE_INFO:
			info, e := pa.GetETypeInfo()
			if e != nil {
				err = krberror.Errorf(e, krberror.EncodingError, "error unmashalling ETYPE-INFO data")
				return
			}
			etypeID = info[0].EType
		}
	}
	etype, e = crypto.GetEtype(etypeID)
	if e != nil {
		err = krberror.Errorf(e, krberror.EncryptingError, "Error creating etype")
		return
	}
	return etype, nil
}
