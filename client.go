package socks5

import (
	"net"
	"fmt"
	"io"
	_ "github.com/daemon369/go-socks5/address"
	_ "errors"
	"github.com/daemon369/go-socks5/common"
	"github.com/daemon369/go-socks5/auth"
	"errors"
	"github.com/daemon369/go-socks5/cmd"
	"github.com/daemon369/go-socks5/address"
)

type Client struct {
	ProxyAddr     string
	Authenticator auth.Authenticator
}

func (c *Client) Connect(addr net.Addr, targetAddr *address.Address) (err error) {

	var remote net.Conn

	remote, err = net.Dial("tcp", c.ProxyAddr)

	if err != nil {
		fmt.Println(err)
		return
	}

	defer remote.Close()

	if _, err = remote.Write([]byte{common.ProtocolVersion, 1, auth.NoAuth}); err != nil {
		fmt.Println(err)
		return
	}

	buf := make([]byte, 2)

	if _, err = io.ReadFull(remote, buf); err != nil {
		fmt.Println(err)
		return
	}

	if err = common.CheckProtocolVersion(buf[0]); err != nil {
		return err
	}

	if c.Authenticator.Method() != int(buf[1]) {
		return errors.New("authenticator method unsupported")
	}

	if auth.NoAcceptable == buf[1] {
		return errors.New("no acceptable method for server")
	}

	buf = []byte{common.ProtocolVersion, cmd.CONNECT, 0x00}
	buf = append(buf, address.FromAddress(targetAddr)...)

	if _, err = remote.Write(buf); err != nil {
		return err
	}

	buf = make([]byte, 4)

	if _, err = io.ReadFull(remote, buf); err != nil {
		return
	}

	if err = common.CheckProtocolVersion(buf[0]); err != nil {
		return err
	}

	if common.Success != buf[1] {
		return errors.New("error happened[" + string(buf[1]) + "]")
	}

	//address.ParseAddress()
	// TODO

	//buf = make([]byte, 0, 6+len(baidu))
	//buf = append(buf, common.ProtocolVersion, 1, 0)
	//
	//if ip := net.ParseIP(baidu); ip != nil {
	//	if ip4 := ip.To4(); ip4 != nil {
	//		ip = ip4
	//		buf = append(buf, address.IPv4)
	//	} else {
	//		buf = append(buf, address.IPv6)
	//	}
	//
	//	buf = append(buf, ip...)
	//} else {
	//	if len(baidu) > 255 {
	//		return errors.New("hostname too long")
	//	}
	//
	//	buf = append(buf, address.FQDN)
	//	buf = append(buf, uint8(len(baidu)))
	//	buf = append(buf, baidu...)
	//}
	//buf = append(buf, byte(port>>8), byte(port))
	//
	//if _, err = remote.Write(buf); err != nil {
	//	fmt.Println(err)
	//	return
	//}
	//
	//if _, err = io.ReadFull(remote, buf[:4]); err != nil {
	//	fmt.Println(err)
	//	return
	//}
	//
	//if 0 != buf[1] {
	//	err = errors.New("connect error :" + string(buf[1]))
	//	fmt.Println(err)
	//	return err
	//}
	//
	//addrLen := 0
	//
	//switch buf[3] {
	//case address.IPv4:
	//	addrLen = net.IPv4len
	//
	//case address.FQDN:
	//	if _, err = io.ReadFull(remote, buf[:1]); err != nil {
	//		fmt.Println(err)
	//		return
	//	}
	//	addrLen = int(buf[0])
	//
	//case address.IPv6:
	//	addrLen = net.IPv6len
	//
	//}
	//
	//buf = make([]byte, addrLen+2)
	//
	//if _, err = io.ReadFull(remote, buf); err != nil {
	//	fmt.Println(err)
	//	return
	//}

	return nil
}
