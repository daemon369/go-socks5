package socks5

import (
	"errors"
	"fmt"
	"io"
	"net"
	"github.com/daemon369/go-socks5/address"
	"github.com/daemon369/go-socks5/auth"
	"github.com/daemon369/go-socks5/cmd"
	"github.com/daemon369/go-socks5/common"
)

type Client struct {
	ProxyAddr     string
	Authenticator auth.Authenticator
	conn          net.Conn
}

func (c *Client) Connect(addr net.Addr, targetAddr *address.Address) (conn net.Conn, err error) {

	var remote net.Conn

	remote, err = net.Dial("tcp", c.ProxyAddr)

	if err != nil {
		fmt.Println(err)
		return
	}

	if _, err = remote.Write([]byte{common.ProtocolVersion, 1, common.NoAuth}); err != nil {
		fmt.Println(err)
		return
	}

	buf := make([]byte, 2)

	if _, err = io.ReadFull(remote, buf); err != nil {
		fmt.Println(err)
		return
	}

	if err = common.CheckProtocolVersion(buf[0]); err != nil {
		return
	}

	if c.Authenticator.Method() != int(buf[1]) {
		return nil, errors.New("authenticator method unsupported")
	}

	if common.NoAcceptable == buf[1] {
		return nil, errors.New("no acceptable method for server")
	}

	buf = []byte{common.ProtocolVersion, cmd.CONNECT, 0x00}
	buf = append(buf, address.FromAddress(targetAddr)...)

	if _, err = remote.Write(buf); err != nil {
		return
	}

	buf = make([]byte, 3)

	if _, err = io.ReadFull(remote, buf); err != nil {
		return
	}

	if err = common.CheckProtocolVersion(buf[0]); err != nil {
		return
	}

	if common.Success != buf[1] {
		return nil, errors.New("error happened[" + string(buf[1]) + "]")
	}

	// ignore address read from server
	if _, err = address.ReadAddress(remote); err != nil {
		return
	}

	return remote, nil
}
