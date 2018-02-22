// Package nametype provides Kerberos 5 principal name type numbers.
package nametype

// Kerberos name type IDs.
const (
	KRB_NT_UNKNOWN        = 0  //Name type not known
	KRB_NT_PRINCIPAL      = 1  //Just the name of the principal as in DCE,  or for users
	KRB_NT_SRV_INST       = 2  //Service and other unique instance (krbtgt)
	KRB_NT_SRV_HST        = 3  //Service with host name as instance (telnet, rcommands)
	KRB_NT_SRV_XHST       = 4  //Service with host as remaining components
	KRB_NT_UID            = 5  //Unique ID
	KRB_NT_X500_PRINCIPAL = 6  //Encoded X.509 Distinguished name [RFC2253]
	KRB_NT_SMTP_NAME      = 7  //Name in form of SMTP email name (e.g., user@example.com)
	KRB_NT_ENTERPRISE     = 10 //Enterprise name; may be mapped to principal name
)
