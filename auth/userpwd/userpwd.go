package userpwd

import (
	"errors"
	"io"
	"net"
	"github.com/daemon369/go-socks5/auth"
)

const (
	VERSION = 0x01
)

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

	for {
		buf := make([]byte, 2)

		if _, err = io.ReadFull(conn, buf); err != nil {
			break
		}

		if VERSION != buf[0] {
			err = errors.New("version of the sub negotiation not supported")
			break
		}

		var userName = ""
		var password = ""

		if buf[1] > 0 {
			buf = make([]byte, buf[1])
			if _, err = io.ReadFull(conn, buf); err != nil {
				break
			}

			userName = string(buf[:])
		}

		buf = make([]byte, 1)
		if _, err = io.ReadFull(conn, buf); err != nil {
			break
		}

		if buf[0] > 0 {
			buf = make([]byte, buf[0])
			if _, err = io.ReadFull(conn, buf); err != nil {
				break
			}

			password = string(buf[:])
		}

		if u.handler == nil {
			err = errors.New("handler can not be nil")
			break
		}

		if !u.handler.handle(userName, password) {
			err = errors.New("username/password not accepted")
			break
		}

		conn.Write([]byte{VERSION, 0x00})

		return nil
	}

	if err != nil {
		conn.Write([]byte{VERSION, 0x01})
	}

	return err
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
