package common

/*
	X'00' NO AUTHENTICATION REQUIRED
	X'01' GSSAPI
	X'02' USERNAME/PASSWORD
	X'03' to X'7F' IANA ASSIGNED
	X'80' to X'FE' RESERVED FOR PRIVATE METHODS
	X'FF' NO ACCEPTABLE METHODS
 */
const (
	NoAuth           = 0x00
	GSSAPI           = 0x01
	UsernamePassword = 0x02
	IANAMin          = 0x03
	IANAMax          = 0x7F
	PrivateMin       = 0x80
	PrivateMax       = 0xFE
	NoAcceptable     = 0xFF
)
