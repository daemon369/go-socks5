package userpwd

import (
	"errors"
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

type UsernamePassword struct {
	provider ClientProvider
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

func New() *UsernamePassword {
	return &UsernamePassword{}
}

func (u *UsernamePassword) SetClientProvider(provider ClientProvider) {
	u.provider = provider
}
