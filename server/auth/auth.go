package auth

import (
	"errors"
	"net"
	"github.com/daemon369/go-socks5/server/auth/reject"
)

// provide user auth
type Authenticator interface {
	// get method id
	Method() (methodId int)

	Authenticate(conn net.Conn, serial int) (err error)
}

type AuthenticatorCenter interface {
	Register(auth Authenticator) (err error)
	Get(methodId int) (auth Authenticator, err error)
}

type authenticatorCenter map[int]Authenticator

func (ac authenticatorCenter) Register(auth Authenticator) (err error) {
	method := auth.Method()

	if _, ok := ac[method]; ok {
		return errors.New("Authenticator for method[" + string(method) + "] has already been registered")
	}
	ac[method] = auth
	return nil
}

func (ac authenticatorCenter) Get(methodId int) (auth Authenticator, err error) {
	auth, ok := ac[methodId]
	if !ok {
		return nil, errors.New("can't find Authenticator for method[" + string(methodId) + "]")
	}

	return auth, nil
}

func New() AuthenticatorCenter {
	ac := authenticatorCenter{}
	ac.Register(reject.New())
	return &ac
}
