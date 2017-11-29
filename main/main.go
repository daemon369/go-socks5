package main

import (
	"fmt"
	"strings"
	"github.com/daemon369/go-socks5"
	"github.com/daemon369/go-socks5/auth"
	"github.com/daemon369/go-socks5/auth/noauth"
	"github.com/daemon369/go-socks5/auth/userpwd"
)

func main() {
	server := socks5.New(":1080")
	fmt.Println("server started success: ", server)

	auth.Register(noauth.New())
	u := userpwd.New()
	u.SetHandlerFunc(func(username, password string) bool {
		if strings.Compare("daemon", username) == 0 && strings.Compare("123456", password) == 0 {
			return true
		} else {
			return false
		}
	})
	auth.Register(u)

	fmt.Println(server)
	server.Serve()
}
