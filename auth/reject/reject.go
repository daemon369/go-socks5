package reject

import (
	"errors"
	"net"
	"github.com/daemon369/go-socks5/auth"
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
	return errors.New("authenticate rejected for method[0xFF]")
}

func New() *Reject {
	return &Reject{*auth.New(auth.NO_ACCEPTABLE)}
}
