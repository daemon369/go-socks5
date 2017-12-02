package socks5

import (
	"testing"
	"github.com/daemon369/go-socks5/auth/noauth"
	"github.com/daemon369/go-socks5/address"
	"os"
	"io"
)

func Test_client(t *testing.T) {
	c := &Client{ProxyAddr: "127.0.0.1:1080", Authenticator: noauth.New()}
	addr := &address.Address{Type: address.FQDN, Host: "www.baidu.com", Port: 443}
	conn, err := c.Connect(addr)

	if err != nil {
		t.Error(err)
		return
	}

	defer conn.Close()

	file, err := os.Create("baidu.html")
	if err != nil {
		t.Error(err)
		return
	}

	defer file.Close()

	buf := make([]byte, 4096)

	n, err := io.ReadFull(conn, buf)

	if err != nil {
		t.Error(err)
		return
	}

	_, err = file.Write(buf[0:n])

	if err != nil {
		t.Error(err)
		return
	}

	t.Log("success")
}
