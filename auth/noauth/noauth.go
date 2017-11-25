package noauth

import (
	"net"
	"github.com/daemon369/go-socks5/auth"
)

func init() {
	auth.Register(New())
}

type NoAuth struct {
	a auth.Authentication
}

func (a *NoAuth) Method() (methodId int) {
	return a.a.Method()
}

func (a *NoAuth) Authenticate(conn net.Conn, serial int) (err error) {
	return nil
}

func New() *NoAuth {
	return &NoAuth{*auth.New(auth.NoAuth)}
}
