package pac

import (
	"encoding/binary"
	"errors"
	"fmt"
	"gopkg.in/jcmturner/gokrb5.v3/crypto"
	"gopkg.in/jcmturner/gokrb5.v3/iana/keyusage"
	"gopkg.in/jcmturner/gokrb5.v3/ndr"
	"gopkg.in/jcmturner/gokrb5.v3/types"
)

// PACType implements: https://msdn.microsoft.com/en-us/library/cc237950.aspx
type PACType struct {
	CBuffers           uint32
	Version            uint32
	Buffers            []InfoBuffer
	Data               []byte
	KerbValidationInfo *KerbValidationInfo
	CredentialsInfo    *CredentialsInfo
	ServerChecksum     *SignatureData
	KDCChecksum        *SignatureData
	ClientInfo         *ClientInfo
	S4UDelegationInfo  *S4UDelegationInfo
	UPNDNSInfo         *UPNDNSInfo
	ClientClaimsInfo   *ClientClaimsInfo
	DeviceInfo         *DeviceInfo
	DeviceClaimsInfo   *DeviceClaimsInfo
	ZeroSigData        []byte
}

// Unmarshal bytes into the PACType struct
func (pac *PACType) Unmarshal(b []byte) error {
	var p int
	var e binary.ByteOrder = binary.LittleEndian
	pac.Data = b
	zb := make([]byte, len(b), len(b))
	copy(zb, b)
	pac.ZeroSigData = zb
	pac.CBuffers = ndr.ReadUint32(&b, &p, &e)
	pac.Version = ndr.ReadUint32(&b, &p, &e)
	buf := make([]InfoBuffer, pac.CBuffers, pac.CBuffers)
	for i := range buf {
		buf[i] = ReadPACInfoBuffer(&b, &p, &e)
	}
	pac.Buffers = buf
	return nil
}

// ProcessPACInfoBuffers processes the PAC Info Buffers.
// https://msdn.microsoft.com/en-us/library/cc237954.aspx
func (pac *PACType) ProcessPACInfoBuffers(key types.EncryptionKey) error {
	for _, buf := range pac.Buffers {
		p := make([]byte, buf.CBBufferSize, buf.CBBufferSize)
		copy(p, pac.Data[int(buf.Offset):int(buf.Offset)+int(buf.CBBufferSize)])
		switch int(buf.ULType) {
		case ulTypeKerbValidationInfo:
			if pac.KerbValidationInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k KerbValidationInfo
			err := k.Unmarshal(p)
			if err != nil {
				return fmt.Errorf("Error processing KerbValidationInfo: %v", err)
			}
			pac.KerbValidationInfo = &k
		case ulTypeCredentials:
			if pac.CredentialsInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k CredentialsInfo
			err := k.Unmarshal(p, key)
			if err != nil {
				return fmt.Errorf("Error processing CredentialsInfo: %v", err)
			}
			pac.CredentialsInfo = &k
		case ulTypePACServerSignatureData:
			if pac.ServerChecksum != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k SignatureData
			zb, err := k.Unmarshal(p)
			copy(pac.ZeroSigData[int(buf.Offset):int(buf.Offset)+int(buf.CBBufferSize)], zb)
			if err != nil {
				return fmt.Errorf("Error processing ServerChecksum: %v", err)
			}
			pac.ServerChecksum = &k
		case ulTypePACKDCSignatureData:
			if pac.KDCChecksum != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k SignatureData
			zb, err := k.Unmarshal(p)
			copy(pac.ZeroSigData[int(buf.Offset):int(buf.Offset)+int(buf.CBBufferSize)], zb)
			if err != nil {
				return fmt.Errorf("Error processing KDCChecksum: %v", err)
			}
			pac.KDCChecksum = &k
		case ulTypePACClientInfo:
			if pac.ClientInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k ClientInfo
			err := k.Unmarshal(p)
			if err != nil {
				return fmt.Errorf("Error processing ClientInfo: %v", err)
			}
			pac.ClientInfo = &k
		case ulTypeS4UDelegationInfo:
			if pac.S4UDelegationInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k S4UDelegationInfo
			err := k.Unmarshal(p)
			if err != nil {
				return fmt.Errorf("Error processing S4U_DelegationInfo: %v", err)
			}
			pac.S4UDelegationInfo = &k
		case ulTypeUPNDNSInfo:
			if pac.UPNDNSInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k UPNDNSInfo
			err := k.Unmarshal(p)
			if err != nil {
				return fmt.Errorf("Error processing UPN_DNSInfo: %v", err)
			}
			pac.UPNDNSInfo = &k
		case ulTypePACClientClaimsInfo:
			if pac.ClientClaimsInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k ClientClaimsInfo
			err := k.Unmarshal(p)
			if err != nil {
				return fmt.Errorf("Error processing ClientClaimsInfo: %v", err)
			}
			pac.ClientClaimsInfo = &k
		case ulTypePACDeviceInfo:
			if pac.DeviceInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k DeviceInfo
			err := k.Unmarshal(p)
			if err != nil {
				return fmt.Errorf("Error processing DeviceInfo: %v", err)
			}
			pac.DeviceInfo = &k
		case ulTypePACDeviceClaimsInfo:
			if pac.DeviceClaimsInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k DeviceClaimsInfo
			err := k.Unmarshal(p)
			if err != nil {
				return fmt.Errorf("Error processing DeviceClaimsInfo: %v", err)
			}
			pac.DeviceClaimsInfo = &k
		}
	}

	if ok, err := pac.validate(key); !ok {
		return err
	}

	return nil
}

func (pac *PACType) validate(key types.EncryptionKey) (bool, error) {
	if pac.KerbValidationInfo == nil {
		return false, errors.New("PAC Info Buffers does not contain a KerbValidationInfo")
	}
	if pac.ServerChecksum == nil {
		return false, errors.New("PAC Info Buffers does not contain a ServerChecksum")
	}
	if pac.KDCChecksum == nil {
		return false, errors.New("PAC Info Buffers does not contain a KDCChecksum")
	}
	if pac.ClientInfo == nil {
		return false, errors.New("PAC Info Buffers does not contain a ClientInfo")
	}
	etype, err := crypto.GetChksumEtype(int(pac.ServerChecksum.SignatureType))
	if err != nil {
		return false, err
	}
	if ok := etype.VerifyChecksum(key.KeyValue,
		pac.ZeroSigData,
		pac.ServerChecksum.Signature,
		keyusage.KERB_NON_KERB_CKSUM_SALT); !ok {
		return false, errors.New("PAC service checksum verification failed")
	}

	return true, nil
}
