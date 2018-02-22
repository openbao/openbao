// Package adtype provides Authenticator type assigned numbers.
package adtype

// Authenticator type IDs.
const (
	ADIfRelevant                  = 1
	ADIntendedForServer           = 2
	ADIntendedForApplicationClass = 3
	ADKDCIssued                   = 4
	ADAndOr                       = 5
	ADMandatoryTicketExtensions   = 6
	ADInTicketExtensions          = 7
	ADMandatoryForKDC             = 8
	OSFDCE                        = 64
	SESAME                        = 65
	ADOSFDCEPKICertID             = 66
	ADAuthenticationStrength      = 70
	ADFXFastArmor                 = 71
	ADFXFastUsed                  = 72
	ADWin2KPAC                    = 128
	ADEtypeNegotiation            = 129
	//Reserved values                   9-63
)
