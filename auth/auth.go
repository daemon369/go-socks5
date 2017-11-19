package auth

import (
	"errors"
	"fmt"
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
	NO_AUTH           = 0x00
	GSSAPI            = 0x01
	USERNAME_PASSWORD = 0x02
	IANA_MIN          = 0x03
	IANA_MAX          = 0x7F
	PRIVATE_MIN       = 0x80
	PRIVATE_MAX       = 0xFE
	NO_ACCEPTABLE     = 0xFF
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
		return nil, errors.New("can't find Authenticator for method[" + string(methodId) + "]")
	}

	return auth, nil
}
