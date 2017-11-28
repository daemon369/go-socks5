package reject

import (
	"errors"
	"net"
	"github.com/daemon369/go-socks5/auth"
)

func init() {
	auth.Register(New())
}

type reject struct {
	a auth.Authentication
}

func (r *reject) Method() (methodId int) {
	return r.a.Method()
}

func (r *reject) Authenticate(conn net.Conn, serial int) (err error) {
	return errors.New("authenticate rejected for method[0xFF]")
}

func New() *reject {
	return &reject{*auth.New(auth.NoAcceptable)}
}
