package kmip

import (
	kmiplib "github.com/ovh/kmip-go"
)

func AlgAndBitLenFromTemplateAttribute(ta kmiplib.TemplateAttribute) (kmiplib.CryptographicAlgorithm, int32) {
	var alg kmiplib.CryptographicAlgorithm
	var bitlen int32

	for _, attr := range ta.Attribute {
		switch attr.AttributeName {
		case kmiplib.AttributeNameCryptographicAlgorithm:
			if v, ok := attr.AttributeValue.(kmiplib.CryptographicAlgorithm); ok {
				alg = v
			}
		case kmiplib.AttributeNameCryptographicLength:
			if v, ok := attr.AttributeValue.(int32); ok {
				bitlen = v
			}
		}
	}
	return alg, bitlen
}

func NameFromTemplateAttribute(ta kmiplib.TemplateAttribute) string {
	for _, attr := range ta.Attribute {
		if attr.AttributeName == kmiplib.AttributeNameName {
			if v, ok := attr.AttributeValue.(kmiplib.Name); ok {
				return v.NameValue
			}
		}
	}
	return ""
}
