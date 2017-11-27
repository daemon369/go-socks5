/*
username/password authenticator

Usage:
	import (
		"strings"
		"github.com/daemon369/go-socks5/auth"
		"github.com/daemon369/go-socks5/auth/usernamepassword"
	)
	...
	server := socks5.New(":1080")
	userNamePassword := usernamepassword.New()
	userNamePassword.SetHandlerFunc(func(username, password string) bool {
		if strings.Compare("myname", username) == 0 && strings.Compare("mypwd", password) == 0 {
			return true
		} else {
			return false
		}
	})
	auth.Register(userNamePassword)
	server.Serve()

For more information, see https://tools.ietf.org/html/rfc1929
 */
package usernamepassword
