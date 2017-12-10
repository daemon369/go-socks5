package noauth

import (
	"net"
	"github.com/daemon369/go-socks5/common"
)

type NoAuth struct {
}

func (a *NoAuth) Method() (methodId int) {
	return common.NoAuth
}

func (a *NoAuth) Client(conn net.Conn) (err error) {
	return nil
}

func (a *NoAuth) Server(conn net.Conn, serial int) (err error) {
	return nil
}

func New() *NoAuth {
	return &NoAuth{}
}
