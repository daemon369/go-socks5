package server

import (
	"fmt"
	"strings"
	"testing"
	"github.com/daemon369/go-socks5/server/auth"
	"github.com/daemon369/go-socks5/server/auth/noauth"
	"github.com/daemon369/go-socks5/server/auth/userpwd"
)

func Test_Serve(t *testing.T) {
	server := New(":1080")

	ret := true
	// register
	ret = auth.Register(noauth.New()) == nil
	u := userpwd.New()
	u.SetServerHandlerFunc(func(username, password string) bool {
		if strings.Compare("daemon", username) == 0 && strings.Compare("123456", password) == 0 {
			return true
		} else {
			return false
		}
	})
	ret = ret && auth.Register(u) == nil

	fmt.Println(server)
	t.Log("server started success")
	server.Serve()

	if ret {
		t.Log("success")
	} else {
		t.Error("failed")
	}
}
