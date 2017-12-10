package auth

import (
	"errors"
	"net"
	"github.com/daemon369/go-socks5/client/auth/reject"
)

func init() {
	Register(reject.New())
}

// provide user auth
type Authenticator interface {
	// get method id
	Method() (methodId int)

	Client(conn net.Conn) (err error)

	Server(conn net.Conn, serial int) (err error)
}

var registerMap = make(map[int]Authenticator)

func Register(auth Authenticator) (err error) {
	method := auth.Method()

	if _, ok := registerMap[method]; ok {
		return errors.New("Authenticator for method[" + string(method) + "] has already been registered")
	}
	registerMap[method] = auth
	return nil
}

func Get(methodId int) (auth Authenticator, err error) {
	auth, ok := registerMap[methodId]
	if !ok {
		return nil, errors.New("can't find Authenticator for method[" + string(methodId) + "]")
	}

	return auth, nil
}
