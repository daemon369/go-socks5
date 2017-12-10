/*
username/password authenticator

NOTICE that server should set their own handlers to provide custom
user verification (default handler accept all username/password)

Usage:
	import (
		"strings"
		"github.com/daemon369/go-socks5/server"
		"github.com/daemon369/go-socks5/server/auth"
		"github.com/daemon369/go-socks5/server/auth/userpwd"
	)
	...
	server := socks5.New(":1080")
	u := userpwd.New()
	u.SetHandlerFunc(func(username, password string) bool {
		if strings.Compare("myname", username) == 0 && strings.Compare("mypwd", password) == 0 {
			return true
		} else {
			return false
		}
	})
	auth.Register(u)
	server.Serve()

For more information, see https://tools.ietf.org/html/rfc1929
 */
package userpwd
