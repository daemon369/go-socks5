package reject

import (
	"net"
	"github.com/daemon369/go-socks5/common"
)

type Reject struct {
}

func (r *Reject) Method() (methodId int) {
	return common.NoAcceptable
}

func (r *Reject) Client(conn net.Conn) (err error) {
	return nil
}

func New() *Reject {
	return &Reject{}
}
