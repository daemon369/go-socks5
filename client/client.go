package client

import (
	"errors"
	"io"
	"log"
	"net"
	"os"
	"github.com/daemon369/go-socks5/address"
	"github.com/daemon369/go-socks5/auth"
	"github.com/daemon369/go-socks5/cmd"
	"github.com/daemon369/go-socks5/common"
)

var logger = log.New(os.Stderr, "Client: ", log.LstdFlags)

type Client struct {
	ProxyAddr     string
	Authenticator auth.Authenticator
	conn          net.Conn
}

func (c *Client) Connect(targetAddr *address.Address) (conn net.Conn, err error) {

	var remote net.Conn

	remote, err = net.Dial("tcp", c.ProxyAddr)

	if err != nil {
		logger.Println(err)
		return
	}

	if _, err = remote.Write([]byte{common.ProtocolVersion, 1, common.NoAuth}); err != nil {
		logger.Println(err)
		return
	}

	buf := make([]byte, 2)

	if _, err = io.ReadFull(remote, buf); err != nil {
		logger.Println(err)
		return
	}

	if err = common.CheckProtocolVersion(buf[0]); err != nil {
		return
	}

	if c.Authenticator.Method() != int(buf[1]) {
		return nil, errors.New("authenticator method unsupported")
	}

	if common.NoAcceptable == buf[1] {
		return nil, errors.New("no acceptable method")
	}

	buf = []byte{common.ProtocolVersion, cmd.CONNECT, 0x00}
	buf = append(buf, targetAddr.ToBytes()...)

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

//func (c *Client) Http(targetUrl string) (content string, err error) {
//	var u *url.URL
//
//	if u, err = url.Parse(targetUrl); err != nil {
//		return
//	}
//
//	addr := &address.Address{}
//
//	var conn net.Conn
//
//	if conn, err = c.Connect(addr); err != nil {
//		return
//	}
//
//	tr := &http.Transport{
//		DialContext:(&net.Dialer{
//
//		}).DialContext
//	}
//	httpClient := &http.Client{Transport: tr}
//
//	return "", nil
//}
