package address

import (
	"net"
	"errors"
)

const (
	Unknown = 0x00
	IPv4    = 0x01
	FQDN    = 0x03
	IPv6    = 0x04
)

func Support(addressType byte) bool {
	return IPv4 == addressType || FQDN == addressType || IPv6 == addressType
}

func ParseAddress(addr string) (addrType int, host string, ip net.IP, err error) {
	addrType = Unknown

	if ip = net.ParseIP(addr); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addrType = IPv4
			ip = ip4
		} else {
			addrType = IPv6
		}

	} else {
		host = addr

		if len(host) <= 0 || len(host) > 255 {
			return Unknown, host, nil, errors.New("host name length illegal")
		}

		addrType = FQDN
	}

	return addrType, host, ip, err
}
