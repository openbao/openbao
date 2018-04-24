package mstypes

import (
	"encoding/binary"

	"gopkg.in/jcmturner/gokrb5.v4/ndr"
)

// ClaimsSetMetadata implements https://msdn.microsoft.com/en-us/library/hh554073.aspx
type ClaimsSetMetadata struct {
	ULClaimsSetSize             uint32
	ClaimsSet                   []byte
	USCompressionFormat         uint32 // Enum see constants below for options
	ULUncompressedClaimsSetSize uint32
	USReservedType              uint16
	ULReservedFieldSize         uint32
	ReservedField               []byte
}

// Compression format assigned numbers.
const (
	CompressionFormatNone       = 0
	CompressionFormatLZNT1      = 2
	CompressionFormatXPress     = 3
	CompressionFormatXPressHuff = 4
)

// ReadClaimsSetMetadata reads a ClaimsSetMetadata from the bytes slice.
func ReadClaimsSetMetadata(b *[]byte, p *int, e *binary.ByteOrder) ClaimsSetMetadata {
	var c ClaimsSetMetadata
	c.ULClaimsSetSize = ndr.ReadUint32(b, p, e)
	c.ClaimsSet = ndr.ReadBytes(b, p, int(c.ULClaimsSetSize), e)
	c.USCompressionFormat = ndr.ReadUint32(b, p, e)
	c.ULUncompressedClaimsSetSize = ndr.ReadUint32(b, p, e)
	c.USReservedType = ndr.ReadUint16(b, p, e)
	c.ULReservedFieldSize = ndr.ReadUint32(b, p, e)
	c.ReservedField = ndr.ReadBytes(b, p, int(c.ULReservedFieldSize), e)
	return c
}
