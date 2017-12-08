/*
Usage:
	srv := server.New(":1080")

	auth.Register(noauth.New())
	u := userpwd.New()
	u.SetHandlerFunc(func(username, password string) bool {
		if strings.Compare("username", username) == 0 && strings.Compare("password", password) == 0 {
			return true
		} else {
			return false
		}
	})
	auth.Register(u)
	srv.Serve()

For more information, see https://tools.ietf.org/html/rfc1928
 */
package server
