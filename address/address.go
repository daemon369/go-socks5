package address

import (
	"errors"
	"fmt"
	"net"
	"strconv"
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

func FromAddr(addr net.Addr) (data []byte) {

	var addrType = Unknown
	var host = "0.0.0.0"
	var ip = net.IP{}
	var port = 0
	var err error

	if addr != nil {
		var portStr = "0"
		host, portStr, err = net.SplitHostPort(addr.String())

		if err == nil {
			addrType, host, ip, err = ParseAddress(host)

			if port, err = strconv.Atoi(portStr); err != nil {
				fmt.Printf("parse local address port failed: %v", err)
			}
		}
	}

	switch addrType {
	case IPv4:
		data = append(data, IPv4)
		data = append(data, ip...)

	case FQDN:
		data = append(data, FQDN)
		data = append(data, uint8(len(host)))
		data = append(data, host...)

	case IPv6:
		data = append(data, IPv6)
		data = append(data, ip...)

	default:
		data = append(data, IPv4)
		data = append(data, net.IPv4zero...)
	}

	data = append(data, byte(port>>8), byte(port))

	return data
}
