package socks5

import (
	"fmt"
	"strings"
	"testing"
	"github.com/daemon369/go-socks5/auth"
	"github.com/daemon369/go-socks5/auth/noauth"
	"github.com/daemon369/go-socks5/auth/usernamepassword"
)

func Test_Serve(t *testing.T) {
	server := New(":7777")

	ret := true
	// register
	ret = auth.Register(noauth.New()) == nil
	userNamePassword := usernamepassword.New()
	userNamePassword.SetHandlerFunc(func(username, password string) bool {
		if strings.Compare("daemon", username) == 0 && strings.Compare("123456", password) == 0 {
			return true
		} else {
			return false
		}
	})
	ret = ret && auth.Register(userNamePassword) == nil

	fmt.Println(server)
	t.Log("server started success")
	server.Serve()

	if ret {
		t.Log("success")
	} else {
		t.Error("failed")
	}
}
