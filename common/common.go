package common

const (
	ProtocolVersion = 0x05
)

const (
	Success                = 0x00
	ServerError            = 0x01
	RefusedByRuleSet       = 0x02
	NetworkUnreachable     = 0x03
	HostUnreachable        = 0x04
	ConnectionRefused      = 0x05
	TTLTimeOut             = 0x06
	CommandUnsupported     = 0x07
	AddressTypeUnsupported = 0x08
)
