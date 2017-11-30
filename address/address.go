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

type Address struct {
	Type int
	Host string
	Ip   net.IP
	Port int
}

func Support(addressType byte) bool {
	return IPv4 == addressType || FQDN == addressType || IPv6 == addressType
}

func ParseAddress(addr string) (address *Address, err error) {
	address = &Address{Type: Unknown}

	if address.Ip = net.ParseIP(addr); address.Ip != nil {
		if ip4 := address.Ip.To4(); ip4 != nil {
			address.Type = IPv4
			address.Ip = ip4
		} else {
			address.Type = IPv6
		}

	} else {
		address.Host = addr

		if len(address.Host) <= 0 || len(address.Host) > 255 {
			return address, errors.New("host name length illegal")
		}

		address.Type = FQDN
	}

	return address, err
}

func FromAddr(addr net.Addr) (data []byte) {

	var err error
	var address = &Address{Type: Unknown, Host: "0.0.0.0", Ip: net.IP{}}

	if addr != nil {
		var portStr = "0"
		address.Host, portStr, err = net.SplitHostPort(addr.String())

		if err == nil {
			address, err = ParseAddress(address.Host)

			if address.Port, err = strconv.Atoi(portStr); err != nil {
				fmt.Printf("parse local address port failed: %v", err)
			}
		}
	}

	return FromAddress(address)
}

func FromAddress(address *Address) (data []byte) {

	switch address.Type {
	case IPv4:
		data = append(data, IPv4)
		data = append(data, address.Ip...)

	case FQDN:
		data = append(data, FQDN)
		data = append(data, uint8(len(address.Host)))
		data = append(data, address.Host...)

	case IPv6:
		data = append(data, IPv6)
		data = append(data, address.Ip...)

	default:
		data = append(data, IPv4)
		data = append(data, net.IPv4zero...)
	}

	data = append(data, byte(address.Port>>8), byte(address.Port))

	return data
}
