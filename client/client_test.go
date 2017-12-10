package client

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"testing"
	"github.com/daemon369/go-socks5/address"
	"github.com/daemon369/go-socks5/client/auth/noauth"
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

	get := "GET / HTTP/1.1\nHost: www.baidu.com\n\n"

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

	for {
		n, err := conn.Read(buf)

		if err == io.EOF {
			break
		}

		if err != nil {
			t.Error(err)
			return
		}

		if n <= 0 {
			break
		}

		_, err = file.Write(buf[0:n])

		if err != nil {
			t.Error(err)
			return
		}
	}

	t.Log("success")
}

func TestClient_Http(t *testing.T) {
	url, err := url.Parse("https://name:pwd@www.test.com:9999/test.html?t1=ll&t2=mm#fragment")

	if err == nil {
		fmt.Println(url)
	}
}
