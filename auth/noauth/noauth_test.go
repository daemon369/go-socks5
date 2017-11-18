package noauth

import (
	"testing"
	"fmt"
	"github.com/daemon369/go-socks5/auth/auth"
)

func Test_noauth(t *testing.T) {
	a := NoAuth{*auth.New(0)}
	fmt.Println(a.Method())
}
