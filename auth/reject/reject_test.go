package reject

import (
	"testing"
	"fmt"
	"github.com/daemon369/go-socks5/auth/auth"
)

func Test_reject(t *testing.T) {
	a := Reject{*auth.New(0)}
	fmt.Println(a.Method())
}

func Test_authenticator(t *testing.T) {
	var a auth.Authenticator
	a = New()
	fmt.Println(a)
}
