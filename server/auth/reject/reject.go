package reject

import (
	"errors"
	"net"
	"github.com/daemon369/go-socks5/common"
)

type reject struct {
}

func (r *reject) Method() (methodId int) {
	return common.NoAcceptable
}

func (r *reject) Authenticate(conn net.Conn, serial int) (err error) {
	return errors.New("no available method")
}

func New() *reject {
	return &reject{}
}
