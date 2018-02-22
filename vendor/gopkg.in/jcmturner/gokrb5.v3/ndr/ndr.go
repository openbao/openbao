// Package ndr is a partial implementation of NDR encoding: http://pubs.opengroup.org/onlinepubs/9629399/chap14.htm
package ndr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
)

/*
Serialization Version 1
https://msdn.microsoft.com/en-us/library/cc243563.aspx

Common Header - https://msdn.microsoft.com/en-us/library/cc243890.aspx
8 bytes in total:
- First byte - Version: Must equal 1
- Second byte -  1st 4 bits: Endianess (0=Big; 1=Little); 2nd 4 bits: Character Encoding (0=ASCII; 1=EBCDIC)
- 3rd - Floating point representation
- 4th - Common Header Length: Must equal 8
- 5th - 8th - Filler: MUST be set to 0xcccccccc on marshaling, and SHOULD be ignored during unmarshaling.

Private Header - https://msdn.microsoft.com/en-us/library/cc243919.aspx
8 bytes in total:
- First 4 bytes - Indicates the length of a serialized top-level type in the octet stream. It MUST include the padding length and exclude the header itself.
- Second 4 bytes - Filler: MUST be set to 0 (zero) during marshaling, and SHOULD be ignored during unmarshaling.
*/

const (
	protocolVersion    = 1
	commonHeaderBytes  = 8
	privateHeaderBytes = 8
	bigEndian          = 0
	littleEndian       = 1
	ascii              = 0
	ebcdic             = 1
	ieee               = 0
	vax                = 1
	cray               = 2
	ibm                = 3
)

// CommonHeader implements the NDR common header: https://msdn.microsoft.com/en-us/library/cc243889.aspx
type CommonHeader struct {
	Version           uint8
	Endianness        binary.ByteOrder
	CharacterEncoding uint8
	//FloatRepresentation uint8
	HeaderLength uint16
	Filler       []byte
}

// PrivateHeader implements the NDR private header: https://msdn.microsoft.com/en-us/library/cc243919.aspx
type PrivateHeader struct {
	ObjectBufferLength uint32
	Filler             []byte
}

// ReadHeaders processes the bytes to return the NDR Common and Private headers.
func ReadHeaders(b *[]byte) (CommonHeader, PrivateHeader, int, error) {
	ch, p, err := GetCommonHeader(b)
	if err != nil {
		return CommonHeader{}, PrivateHeader{}, 0, err
	}
	ph, err := GetPrivateHeader(b, &p, &ch.Endianness)
	if err != nil {
		return CommonHeader{}, PrivateHeader{}, 0, err
	}
	return ch, ph, p, err
}

// GetCommonHeader processes the bytes to return the NDR Common header.
func GetCommonHeader(b *[]byte) (CommonHeader, int, error) {
	//The first 8 bytes comprise the Common RPC Header for type marshalling.
	if len(*b) < commonHeaderBytes {
		return CommonHeader{}, 0, Malformed{EText: "Not enough bytes."}
	}
	if (*b)[0] != protocolVersion {
		return CommonHeader{}, 0, Malformed{EText: fmt.Sprintf("Stream does not indicate a RPC Type serialization of version %v", protocolVersion)}
	}
	endian := int((*b)[1] >> 4 & 0xF)
	if endian != 0 && endian != 1 {
		return CommonHeader{}, 1, Malformed{EText: "Common header does not indicate a valid endianness"}
	}
	charEncoding := uint8((*b)[1] & 0xF)
	if charEncoding != 0 && charEncoding != 1 {
		return CommonHeader{}, 1, Malformed{EText: "Common header does not indicate a valid charater encoding"}
	}
	var bo binary.ByteOrder
	switch endian {
	case littleEndian:
		bo = binary.LittleEndian
	case bigEndian:
		bo = binary.BigEndian
	}
	l := bo.Uint16((*b)[2:4])
	if l != commonHeaderBytes {
		return CommonHeader{}, 4, Malformed{EText: fmt.Sprintf("Common header does not indicate a valid length: %v instead of %v", uint8((*b)[3]), commonHeaderBytes)}
	}

	return CommonHeader{
		Version:           uint8((*b)[0]),
		Endianness:        bo,
		CharacterEncoding: charEncoding,
		//FloatRepresentation: uint8(b[2]),
		HeaderLength: l,
		Filler:       (*b)[4:8],
	}, 8, nil
}

// GetPrivateHeader processes the bytes to return the NDR Private header.
func GetPrivateHeader(b *[]byte, p *int, bo *binary.ByteOrder) (PrivateHeader, error) {
	//The next 8 bytes comprise the RPC type marshalling private header for constructed types.
	if len(*b) < (privateHeaderBytes) {
		return PrivateHeader{}, Malformed{EText: "Not enough bytes."}
	}
	var l uint32
	buf := bytes.NewBuffer((*b)[*p : *p+4])
	binary.Read(buf, *bo, &l)
	if l%8 != 0 {
		return PrivateHeader{}, Malformed{EText: "Object buffer length not a multiple of 8"}
	}
	*p += 8
	return PrivateHeader{
		ObjectBufferLength: l,
		Filler:             (*b)[4:8],
	}, nil
}

// ReadUint8 reads bytes representing a thirty two bit integer.
func ReadUint8(b *[]byte, p *int) (i uint8) {
	if len((*b)[*p:]) < 1 {
		return
	}
	ensureAlignment(p, 1)
	i = uint8((*b)[*p])
	*p++
	return
}

// ReadUint16 reads bytes representing a thirty two bit integer.
func ReadUint16(b *[]byte, p *int, e *binary.ByteOrder) (i uint16) {
	if len((*b)[*p:]) < 2 {
		return
	}
	ensureAlignment(p, 2)
	i = (*e).Uint16((*b)[*p : *p+2])
	*p += 2
	return
}

// ReadUint32 reads bytes representing a thirty two bit integer.
func ReadUint32(b *[]byte, p *int, e *binary.ByteOrder) (i uint32) {
	if len((*b)[*p:]) < 4 {
		return
	}
	ensureAlignment(p, 4)
	i = (*e).Uint32((*b)[*p : *p+4])
	*p += 4
	return
}

// ReadUint64 reads bytes representing a thirty two bit integer.
func ReadUint64(b *[]byte, p *int, e *binary.ByteOrder) (i uint64) {
	if len((*b)[*p:]) < 8 {
		return
	}
	ensureAlignment(p, 8)
	i = (*e).Uint64((*b)[*p : *p+8])
	*p += 8
	return
}

// ReadBytes reads the number of bytes specified.
func ReadBytes(b *[]byte, p *int, s int, e *binary.ByteOrder) (r []byte) {
	if len((*b)[*p:]) < s {
		return
	}
	buf := bytes.NewBuffer((*b)[*p : *p+s])
	r = make([]byte, s)
	binary.Read(buf, *e, &r)
	*p += s
	return r
}

// ReadBool reads bytes representing a boolean.
func ReadBool(b *[]byte, p *int) bool {
	if len((*b)[*p:]) < 1 {
		return false
	}
	if ReadUint8(b, p) != 0 {
		return true
	}
	return false
}

// ReadIEEEfloat32 reads bytes representing a IEEE formatted 32 bit float.
func ReadIEEEfloat32(b *[]byte, p *int, e *binary.ByteOrder) float32 {
	ensureAlignment(p, 4)
	return math.Float32frombits(ReadUint32(b, p, e))
}

// ReadIEEEfloat64 reads bytes representing a IEEE formatted 64 bit float.
func ReadIEEEfloat64(b *[]byte, p *int, e *binary.ByteOrder) float64 {
	ensureAlignment(p, 8)
	return math.Float64frombits(ReadUint64(b, p, e))
}

// ReadConformantVaryingString reads a Conformant and Varying String from the bytes slice.
// A conformant and varying string is a string in which the maximum number of elements is not known beforehand and therefore is included in the representation of the string.
// NDR represents a conformant and varying string as an ordered sequence of representations of the string elements, preceded by three unsigned long integers.
// The first integer gives the maximum number of elements in the string, including the terminator.
// The second integer gives the offset from the first index of the string to the first index of the actual subset being passed.
// The third integer gives the actual number of elements being passed, including the terminator.
func ReadConformantVaryingString(b *[]byte, p *int, e *binary.ByteOrder) (string, error) {
	m := ReadUint32(b, p, e) // Max element count
	o := ReadUint32(b, p, e) // Offset
	a := ReadUint32(b, p, e) // Actual count
	if a > (m-o) || o > m {
		return "", Malformed{EText: fmt.Sprintf("Not enough bytes. Max: %d, Offset: %d, Actual: %d", m, o, a)}
	}
	//Unicode string so each element is 2 bytes
	//move position based on the offset
	if o > 0 {
		*p += int(o * 2)
	}
	s := make([]rune, a, a)
	for i := 0; i < len(s); i++ {
		s[i] = rune(ReadUint16(b, p, e))
	}
	ensureAlignment(p, 4)
	return string(s), nil
}

// ReadUniDimensionalConformantArrayHeader reads a UniDimensionalConformantArrayHeader from the bytes slice.
func ReadUniDimensionalConformantArrayHeader(b *[]byte, p *int, e *binary.ByteOrder) int {
	return int(ReadUint32(b, p, e))
}

func ensureAlignment(p *int, byteSize int) {
	if byteSize > 0 {
		if s := *p % byteSize; s != 0 {
			*p += byteSize - s
		}
	}
}
