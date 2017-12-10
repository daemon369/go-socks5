package userpwd

import (
	"errors"
	"io"
	"net"
	"github.com/daemon369/go-socks5/common"
)

const (
	VERSION = 0x01
	MaxLen  = 0xff
)

type ClientProvider interface {
	Provide() (username, password string, err error)
}

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
	provider ClientProvider
	handler  ServerHandler
}

func (u *UsernamePassword) Method() (methodId int) {
	return common.UsernamePassword
}

func (u *UsernamePassword) Client(conn net.Conn) (err error) {
	if u.provider == nil {
		return errors.New("client provider can't be nil, use SetClientProvider to set it")
	}

	var usr, pwd string
	usr, pwd, err = u.provider.Provide()

	if err != nil {
		return err
	}

	usrLen := len(usr)
	pwdLen := len(pwd)

	if usrLen > MaxLen {
		return errors.New("length of username out of limit(" + string(MaxLen) + ")")
	}

	if pwdLen > MaxLen {
		return errors.New("length of password out of limit(" + string(MaxLen) + ")")
	}

	buf := []byte{VERSION}

	buf = append(buf, byte(usrLen))
	buf = append(buf, usr...)

	buf = append(buf, byte(pwdLen))
	buf = append(buf, pwd...)

	if _, err = conn.Write(buf); err != nil {
		return err
	}

	return nil
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

func (u *UsernamePassword) SetClientProvider(provider ClientProvider) {
	u.provider = provider
}

func (u *UsernamePassword) SetServerHandler(handler ServerHandler) {
	u.handler = handler
}

func (u *UsernamePassword) SetServerHandlerFunc(f func(username, password string) bool) {
	u.handler = ServerHandlerFunc(f)
}
