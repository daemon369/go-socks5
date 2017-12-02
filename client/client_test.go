package client

import (
	"os"
	"testing"
	"github.com/daemon369/go-socks5/auth/noauth"
	"github.com/daemon369/go-socks5/address"
)

func Test_client(t *testing.T) {
	c := &Client{ProxyAddr: "127.0.0.1:1080", Authenticator: noauth.New()}
	addr := &address.Address{Type: address.FQDN, Host: "www.baidu.com", Port: 80}
	conn, err := c.Connect(addr)

	if err != nil {
		t.Error(err)
		return
	}

	defer conn.Close()

	get := "GET / HTTP/1.1\n\n"

	if _, err = conn.Write([]byte(get)); err != nil {
		t.Error(err)
		return
	}

	file, err := os.Create("baidu.html")
	if err != nil {
		t.Error(err)
		return
	}

	defer file.Close()

	buf := make([]byte, 4096)

	n, err := conn.Read(buf)

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
