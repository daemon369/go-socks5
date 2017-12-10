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

type Provider interface {
	Provide() (username, password string, err error)
}

type ProviderFunc func() (username, password string, err error)

func (f ProviderFunc) Provide() (username, password string, err error) {
	return f()
}

type UsernamePassword struct {
	provider Provider
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
func (u *UsernamePassword) Authenticate(conn net.Conn) (err error) {
	if u.provider == nil {
		return errors.New("client provider can't be nil, use SetProvider to set it")
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

func (u *UsernamePassword) SetProvider(provider Provider) {
	u.provider = provider
}

func (u *UsernamePassword) SetProviderFunc(f func() (username, password string, err error)) {
	u.provider = ProviderFunc(f)
}

func New() *UsernamePassword {
	return &UsernamePassword{}
}
