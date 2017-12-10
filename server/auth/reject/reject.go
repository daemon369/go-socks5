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

func (r *Reject) Server(conn net.Conn, serial int) (err error) {
	return errors.New("no available method")
}

func New() *Reject {
	return &Reject{}
}
