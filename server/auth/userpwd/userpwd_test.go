package userpwd_test

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
	"github.com/daemon369/go-socks5/server/auth/userpwd"
	"github.com/daemon369/go-socks5/test/conn"
)

func Test_UsernamePasswordHandlerFuc(t *testing.T) {
	u := userpwd.New()
	u.SetHandlerFunc(func(username, password string) bool {
		if strings.Compare("daemon", username) == 0 && strings.Compare("123456", password) == 0 {
			return true
		} else {
			return false
		}
	})

	user := "daemon"
	pwd := "123456"

	var buf []byte

	buf = []byte{0x01}
	buf = append(buf, byte(len(user)))
	buf = append(buf, user...)
	buf = append(buf, byte(len(pwd)))
	buf = append(buf, pwd...)

	c := &conn.TestConn{}
	c.Write(buf)

	var err error

	ch := make(chan error, 1)

	go func(c net.Conn, ch chan error) {
		ch <- u.Authenticate(c, 0)
	}(c.Reverse(), ch)

	type data struct {
		err error
		buf []byte
	}

	ch2 := make(chan data, 1)

	go func(c net.Conn, ch chan data) {
		time.Sleep(2000)
		buf = make([]byte, 2)

		if _, err = io.ReadFull(c, buf); err != nil {
			t.Error("failed", err)
			ch <- data{err, nil}
		} else {
			ch <- data{nil, buf}
		}
	}(c.Reverse(), ch2)

	select {
	case err = <-ch:
		if err != nil {
			t.Error(err)
			return
		}

	case d := <-ch2:
		if d.err != nil {
			t.Error(err)
			return
		}

		if userpwd.VERSION != d.buf[0] || 0 != d.buf[1] {
			t.Error("failed", err, buf[0], buf[1])
			return
		}
	}

	t.Log("success")
}
