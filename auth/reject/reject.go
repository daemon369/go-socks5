package reject

import (
	"net"
	e "errors"
	"github.com/daemon369/go-socks5/auth/auth"
)

func init() {
	auth.Register(New())
}

type Reject struct {
	a auth.Authentication
}

func (r *Reject) Method() (methodId int) {
	return r.a.Method()
}

func (r *Reject) Authenticate(conn net.Conn, serial int) (err error) {
	return e.New("authenticate rejected for method[0xFF]")
}

func New() *Reject {
	return &Reject{*auth.New(0xff)}
}
