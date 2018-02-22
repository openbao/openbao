// Package chksumtype provides Kerberos 5 checksum type assigned numbers.
package chksumtype

// Checksum type IDs.
const (
	//RESERVED : 0
	CRC32         = 1
	RSA_MD4       = 2
	RSA_MD4_DES   = 3
	DES_MAC       = 4
	DES_MAC_K     = 5
	RSA_MD4_DES_K = 6
	RSA_MD5       = 7
	RSA_MD5_DES   = 8
	RSA_MD5_DES3  = 9
	SHA1_ID10     = 10
	//UNASSIGNED : 11
	HMAC_SHA1_DES3_KD      = 12
	HMAC_SHA1_DES3         = 13
	SHA1_ID14              = 14
	HMAC_SHA1_96_AES128    = 15
	HMAC_SHA1_96_AES256    = 16
	CMAC_CAMELLIA128       = 17
	CMAC_CAMELLIA256       = 18
	HMAC_SHA256_128_AES128 = 19
	HMAC_SHA384_192_AES256 = 20
	//UNASSIGNED : 21-32770
	GSSAPI = 32771
	//UNASSIGNED : 32772-2147483647
	KERB_CHECKSUM_HMAC_MD5_UNSIGNED = 4294967158 // 0xFFFFFF76 documentation says this is -138 but in an unsigned int this is 4294967158
	KERB_CHECKSUM_HMAC_MD5          = -138
)
