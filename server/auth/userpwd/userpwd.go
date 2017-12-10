package userpwd

import (
	"errors"
	"io"
	"net"
	"github.com/daemon369/go-socks5/common"
)

const (
	VERSION = 0x01
)

type ServerHandler interface {
	handle(username, password string) bool
}

type ServerHandlerFunc func(username, password string) bool

func (f ServerHandlerFunc) handle(username, password string) bool {
	return f.handle(username, password)
}

// default server handler accept all username/password
var defaultServerHandler = ServerHandlerFunc(func(username, password string) bool { return true })

type UsernamePassword struct {
	handler ServerHandler
}

func (u *UsernamePassword) Method() (methodId int) {
	return common.UsernamePassword
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
func (u *UsernamePassword) Server(conn net.Conn, serial int) (err error) {

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
			handler = defaultServerHandler
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
	return &UsernamePassword{}
}

func (u *UsernamePassword) SetServerHandler(handler ServerHandler) {
	u.handler = handler
}

func (u *UsernamePassword) SetServerHandlerFunc(f func(username, password string) bool) {
	u.handler = ServerHandlerFunc(f)
}
