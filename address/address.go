package address

import (
	"errors"
	"fmt"
	"io"
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
	Type byte
	Host string
	Ip   net.IP
	Port int
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

	return address.ToBytes()
}

func (address *Address) ToBytes() (data []byte) {

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

/*
read address type, address and port from net.Conn

	+------+----------+----------+
	| ATYP |   ADDR   |   PORT   |
	+------+----------+----------+
	|  1   | Variable |    2     |
	+------+----------+----------+
 */
func ReadAddress(conn net.Conn) (address *Address, err error) {
	buf := make([]byte, 1)

	if _, err = io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	addrType := buf[0]
	address = &Address{}

	var addrLen byte = 0

	switch addrType {
	case IPv4:
		address.Type = IPv4
		addrLen = net.IPv4len
	case IPv6:
		address.Type = IPv6
		addrLen = net.IPv6len
	case FQDN:
		address.Type = FQDN
		if _, err = io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		addrLen = buf[0]
		if buf[0] == 0 {
			return nil, errors.New("host length can't be 0")
		}

	default:
		return nil, errors.New("unsupported address type: " + string(addrType))
	}

	buf = make([]byte, addrLen)

	if _, err = io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	switch addrType {
	case IPv4, IPv6:
		address.Host = net.IP(buf).String()
	case FQDN:
		address.Host = string(buf)
	}

	if _, err = io.ReadFull(conn, buf[:2]); err != nil {
		return nil, err
	}

	address.Port = int(uint16(buf[0])<<8 | uint16(buf[1]))

	return address, nil
}
