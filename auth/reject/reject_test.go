package reject

import (
	"testing"
	"fmt"
	"github.com/daemon369/go-socks5/auth"
)

func Test_reject(t *testing.T) {
	a := reject{*auth.New(0)}
	fmt.Println(a.Method())
}

func Test_authenticator(t *testing.T) {
	var a auth.Authenticator
	a = New()
	fmt.Println(a)
}
