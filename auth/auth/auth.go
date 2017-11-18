package auth

import (
	"net"
	"fmt"
	e "github.com/daemon369/go-socks5/error"
)

// provide user auth
type Authenticator interface {
	// get method id
	Method() (methodId int)

	// authenticate user
	Authenticate(conn net.Conn, serial int) (err error)
}

type Authentication struct {
	method int
}

func New(methodId int) *Authentication {
	return &Authentication{methodId}
}

func (a *Authentication) Method() (methodId int) {
	methodId = a.method
	return
}

var registerMap = make(map[int]Authenticator)

func Register(auth Authenticator) {
	method := auth.Method()

	if _, ok := registerMap[method]; ok {
		fmt.Printf("Authenticator for method[%d] has already been registered", method)
		return
	}
	registerMap[method] = auth
}

func Get(methodId int) (auth Authenticator, err error) {
	auth, ok := registerMap[methodId]
	if !ok {
		return nil, e.New("can't find Authenticator for method[" + string(methodId) + "]")
	}

	return auth, nil
}
