package types

import "strings"

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.2.2

// PrincipalName implements RFC 4120 type: https://tools.ietf.org/html/rfc4120#section-5.2.2
type PrincipalName struct {
	NameType   int32    `asn1:"explicit,tag:0"`
	NameString []string `asn1:"generalstring,explicit,tag:1"`
}

// GetSalt returns a salt derived from the PrincipalName.
func (pn *PrincipalName) GetSalt(realm string) string {
	var sb []byte
	sb = append(sb, realm...)
	for _, n := range pn.NameString {
		sb = append(sb, n...)
	}
	return string(sb)
}

// Equal tests if the PrincipalName is equal to the one provided.
func (pn *PrincipalName) Equal(n PrincipalName) bool {
	if n.NameType != pn.NameType {
		return false
	}
	for i, s := range pn.NameString {
		if n.NameString[i] != s {
			return false
		}
	}
	return true
}

// GetPrincipalNameString returns the PrincipalName in string form.
func (pn *PrincipalName) GetPrincipalNameString() string {
	return strings.Join(pn.NameString, "/")
}
