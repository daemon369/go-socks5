package main

import (
	"fmt"
	"strings"
	"github.com/daemon369/go-socks5/server"
	"github.com/daemon369/go-socks5/server/auth/noauth"
	"github.com/daemon369/go-socks5/server/auth/userpwd"
)

func main() {
	srv := server.New(":1080")

	srv.AuthenticatorCenter.Register(noauth.New())
	u := userpwd.New()
	u.SetHandlerFunc(func(username, password string) bool {
		if strings.Compare("daemon", username) == 0 && strings.Compare("123456", password) == 0 {
			return true
		} else {
			return false
		}
	})
	srv.AuthenticatorCenter.Register(u)

	fmt.Println(srv)
	srv.Serve()
}
