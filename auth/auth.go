package auth

import (
	"errors"
	"net"
)

/*
	X'00' NO AUTHENTICATION REQUIRED
	X'01' GSSAPI
	X'02' USERNAME/PASSWORD
	X'03' to X'7F' IANA ASSIGNED
	X'80' to X'FE' RESERVED FOR PRIVATE METHODS
	X'FF' NO ACCEPTABLE METHODS
 */
const (
	NoAuth           = 0x00
	GSSAPI           = 0x01
	UsernamePassword = 0x02
	IANAMin          = 0x03
	IANAMax          = 0x7F
	PrivateMin       = 0x80
	PrivateMax       = 0xFE
	NoAcceptable     = 0xFF
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
