package address

const (
	Unknown = 0x00
	IPv4    = 0x01
	FQDN    = 0x02
	IPv6    = 0x03
)

func Support(addressType byte) bool {
	return IPv4 == addressType || FQDN == addressType || IPv6 == addressType
}
