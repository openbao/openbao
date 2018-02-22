// Package keytab implements Kerberos keytabs: https://web.mit.edu/kerberos/krb5-devel/doc/formats/keytab_file_format.html.
package keytab

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"gopkg.in/jcmturner/gokrb5.v3/types"
	"io/ioutil"
	"time"
	"unsafe"
)

// Keytab struct.
type Keytab struct {
	Version uint16
	Entries []entry
}

// Keytab entry struct.
type entry struct {
	Principal principal
	Timestamp time.Time
	KVNO8     uint8
	Key       types.EncryptionKey
	KVNO      uint32
}

// Keytab entry principal struct.
type principal struct {
	NumComponents int16
	Realm         string
	Components    []string
	NameType      int32
}

// NewKeytab creates new, empty Keytab type.
func NewKeytab() Keytab {
	var e []entry
	return Keytab{
		Version: 0,
		Entries: e,
	}
}

// GetEncryptionKey returns the EncryptionKey from the Keytab for the newest entry with the required kvno, etype and matching principal.
func (kt *Keytab) GetEncryptionKey(nameString []string, realm string, kvno, etype int) (types.EncryptionKey, error) {
	var key types.EncryptionKey
	var t time.Time
	for _, k := range kt.Entries {
		if k.Principal.Realm == realm && len(k.Principal.Components) == len(nameString) && int(k.Key.KeyType) == etype && (int(k.KVNO) == kvno || kvno == 0) && k.Timestamp.After(t) {
			p := true
			for i, n := range k.Principal.Components {
				if nameString[i] != n {
					p = false
					break
				}
			}
			if p {
				key = k.Key
			}
		}
	}
	if len(key.KeyValue) < 1 {
		return key, fmt.Errorf("Matching key not found in keytab. Looking for %v realm: %v kvno: %v etype: %v", nameString, realm, kvno, etype)
	}
	return key, nil
}

// Create a new Keytab entry.
func newKeytabEntry() entry {
	var b []byte
	return entry{
		Principal: newPrincipal(),
		Timestamp: time.Time{},
		KVNO8:     0,
		Key: types.EncryptionKey{
			KeyType:  0,
			KeyValue: b,
		},
		KVNO: 0,
	}
}

// Create a new principal.
func newPrincipal() principal {
	var c []string
	return principal{
		NumComponents: 0,
		Realm:         "",
		Components:    c,
		NameType:      0,
	}
}

// Load a Keytab file into a Keytab type.
func Load(ktPath string) (kt Keytab, err error) {
	k, err := ioutil.ReadFile(ktPath)
	if err != nil {
		return
	}
	return Parse(k)
}

// Parse byte slice of Keytab data into Keytab type.
func Parse(b []byte) (kt Keytab, err error) {
	//The first byte of the file always has the value 5
	if int8(b[0]) != 5 {
		err = errors.New("Invalid keytab data. First byte does not equal 5")
		return
	}
	//Get keytab version
	//The second byte contains the version number (1 or 2)
	kt.Version = uint16(b[1])
	if kt.Version != 1 && kt.Version != 2 {
		err = errors.New("Invalid keytab data. Keytab version is neither 1 nor 2")
		return
	}
	//Version 1 of the file format uses native byte order for integer representations. Version 2 always uses big-endian byte order
	var endian binary.ByteOrder
	endian = binary.BigEndian
	if kt.Version == 1 && isNativeEndianLittle() {
		endian = binary.LittleEndian
	}
	/*
		After the two-byte version indicator, the file contains a sequence of signed 32-bit record lengths followed by key records or holes.
		A positive record length indicates a valid key entry whose size is equal to or less than the record length.
		A negative length indicates a zero-filled hole whose size is the inverse of the length.
		A length of 0 indicates the end of the file.
	*/
	// n tracks position in the byte array
	n := 2
	l := readInt32(b, &n, &endian)
	for l != 0 {
		if l < 0 {
			//Zero padded so skip over
			l = l * -1
			n = n + int(l)
		} else {
			//fmt.Printf("Bytes for entry: %v\n", b[n:n+int(l)])
			eb := b[n : n+int(l)]
			n = n + int(l)
			ke := newKeytabEntry()
			// p keeps track as to where we are in the byte stream
			var p int
			parsePrincipal(eb, &p, &kt, &ke, &endian)
			ke.Timestamp = readTimestamp(eb, &p, &endian)
			ke.KVNO8 = uint8(readInt8(eb, &p, &endian))
			ke.Key.KeyType = int(readInt16(eb, &p, &endian))
			kl := int(readInt16(eb, &p, &endian))
			ke.Key.KeyValue = readBytes(eb, &p, kl, &endian)
			//The 32-bit key version overrides the 8-bit key version.
			// To determine if it is present, the implementation must check that at least 4 bytes remain in the record after the other fields are read,
			// and that the value of the 32-bit integer contained in those bytes is non-zero.
			if len(eb)-p >= 4 {
				// The 32-bit key may be present
				ke.KVNO = uint32(readInt32(eb, &p, &endian))
			}
			if ke.KVNO == 0 {
				// Handles if the value from the last 4 bytes was zero and also if there are not the 4 bytes present. Makes sense to put the same value here as KVNO8
				ke.KVNO = uint32(ke.KVNO8)
			}
			// Add the entry to the keytab
			kt.Entries = append(kt.Entries, ke)
		}
		// Check if there are still 4 bytes left to read
		if n > len(b) || len(b[n:]) < 4 {
			break
		}
		// Read the size of the next entry
		l = readInt32(b, &n, &endian)
	}
	return
}

// Parse the Keytab bytes of a principal into a Keytab entry's principal.
func parsePrincipal(b []byte, p *int, kt *Keytab, ke *entry, e *binary.ByteOrder) (err error) {
	ke.Principal.NumComponents = readInt16(b, p, e)
	if kt.Version == 1 {
		//In version 1 the number of components includes the realm. Minus 1 to make consistent with version 2
		ke.Principal.NumComponents--
	}
	lenRealm := readInt16(b, p, e)
	ke.Principal.Realm = string(readBytes(b, p, int(lenRealm), e))
	for i := 0; i < int(ke.Principal.NumComponents); i++ {
		l := readInt16(b, p, e)
		ke.Principal.Components = append(ke.Principal.Components, string(readBytes(b, p, int(l), e)))
	}
	if kt.Version != 1 {
		//Name Type is omitted in version 1
		ke.Principal.NameType = readInt32(b, p, e)
	}
	return
}

// Read bytes representing a timestamp.
func readTimestamp(b []byte, p *int, e *binary.ByteOrder) time.Time {
	return time.Unix(int64(readInt32(b, p, e)), 0)
}

// Read bytes representing an eight bit integer.
func readInt8(b []byte, p *int, e *binary.ByteOrder) (i int8) {
	buf := bytes.NewBuffer(b[*p : *p+1])
	binary.Read(buf, *e, &i)
	*p++
	return
}

// Read bytes representing a sixteen bit integer.
func readInt16(b []byte, p *int, e *binary.ByteOrder) (i int16) {
	buf := bytes.NewBuffer(b[*p : *p+2])
	binary.Read(buf, *e, &i)
	*p += 2
	return
}

// Read bytes representing a thirty two bit integer.
func readInt32(b []byte, p *int, e *binary.ByteOrder) (i int32) {
	buf := bytes.NewBuffer(b[*p : *p+4])
	binary.Read(buf, *e, &i)
	*p += 4
	return
}

func readBytes(b []byte, p *int, s int, e *binary.ByteOrder) []byte {
	buf := bytes.NewBuffer(b[*p : *p+s])
	r := make([]byte, s)
	binary.Read(buf, *e, &r)
	*p += s
	return r
}

func isNativeEndianLittle() bool {
	var x = 0x012345678
	var p = unsafe.Pointer(&x)
	var bp = (*[4]byte)(p)

	var endian bool
	if 0x01 == bp[0] {
		endian = false
	} else if (0x78 & 0xff) == (bp[0] & 0xff) {
		endian = true
	} else {
		// Default to big endian
		endian = false
	}
	return endian
}
