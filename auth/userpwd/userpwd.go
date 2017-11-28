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

type UsernamePassword struct {
	a       auth.Authentication
	handler Handler
}

func (u *UsernamePassword) Method() (methodId int) {
	return u.a.Method()
}

/*
1. client send a username/password request

	+----+------+----------+------+----------+
	|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	+----+------+----------+------+----------+
	| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
	+----+------+----------+------+----------+

2. server verifies request and send response with version & status,
   0x00 indicates success and other values indicate failure

	+----+--------+
	|VER | STATUS |
	+----+--------+
	|  1 |   1    |
	+----+--------+
*/
func (u *UsernamePassword) Authenticate(conn net.Conn, serial int) (err error) {

	for {
		buf := make([]byte, 2)

		if _, err = io.ReadFull(conn, buf); err != nil {
			break
		}

		if VERSION != buf[0] {
			err = errors.New("version of the sub negotiation not supported")
			break
		}

		var username = ""
		var password = ""

		if buf[1] > 0 {
			buf = make([]byte, buf[1])
			if _, err = io.ReadFull(conn, buf); err != nil {
				break
			}

			username = string(buf[:])
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

		handler := u.handler

		if handler == nil {
			handler = defaultHandler
		}

		if !handler.handle(username, password) {
			err = errors.New("username/password not accepted")
			break
		}

		conn.Write([]byte{VERSION, 0x00}) // should we care the result?

		return nil
	}

	if err != nil {
		conn.Write([]byte{VERSION, 0x01})
	}

	return err
}

func New() *UsernamePassword {
	return &UsernamePassword{a: *auth.New(auth.UsernamePassword)}
}

func (u *UsernamePassword) SetHandler(handler Handler) {
	u.handler = handler
}

func (u *UsernamePassword) SetHandlerFunc(f func(username, password string) bool) {
	u.handler = HandlerFunc(f)
}
