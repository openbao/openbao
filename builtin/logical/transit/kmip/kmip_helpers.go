package kmip

import (
	"github.com/ovh/kmip-go"
	kmiplib "github.com/ovh/kmip-go"
)

func AlgAndBitLenFromTemplateAttribute(ta kmiplib.TemplateAttribute) (kmiplib.CryptographicAlgorithm, int) {
	var alg kmiplib.CryptographicAlgorithm
	var bitlen int

	for _, attr := range ta.Attribute {
		switch attr.AttributeName {
		case kmip.AttributeNameCryptographicAlgorithm:
			if v, ok := attr.AttributeValue.(kmiplib.CryptographicAlgorithm); ok {
				alg = v
			}
		case kmip.AttributeNameCryptographicLength:
			if v, ok := attr.AttributeValue.(int); ok {
				bitlen = v
			}
		}
	}
	return alg, bitlen
}
