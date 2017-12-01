package reject

import (
	"errors"
	"net"
	"github.com/daemon369/go-socks5/common"
)

type Reject struct {
}

func (r *Reject) Method() (methodId int) {
	return common.NoAcceptable
}

func (r *Reject) Authenticate(conn net.Conn, serial int) (err error) {
	return errors.New("authenticate rejected for method[0xFF]")
}

func New() *Reject {
	return &Reject{}
}
