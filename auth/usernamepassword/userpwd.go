package usernamepassword

import (
	"net"
	"github.com/daemon369/go-socks5/auth"
)

func init() {
	//auth.Register(New())
}

type Handler interface {
	handle(username, password string) bool
}

type HandlerFunc func(username, password string) bool

func (f HandlerFunc) handle(username, password string) bool {
	return f.handle(username, password)
}

// default handler accept all username/password
var defaultHandler = HandlerFunc(func(username, password string) bool { return true })

type UserNamePassword struct {
	a       auth.Authentication
	handler Handler
}

func (u *UserNamePassword) Method() (methodId int) {
	return u.a.Method()
}

func (u *UserNamePassword) Authenticate(conn net.Conn, serial int) (err error) {
	return nil // TODO
}

func New() *UserNamePassword {
	return &UserNamePassword{a: *auth.New(auth.UsernamePassword), handler: defaultHandler}
}

func (u *UserNamePassword) SetHandler(handler Handler) {
	u.handler = handler
}

func (u *UserNamePassword) SetHandlerFunc(f func(username, password string) bool) {
	u.handler = HandlerFunc(f)
}
