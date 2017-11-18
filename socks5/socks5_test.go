package socks5

import (
	"testing"
)

func Test_Serve(t *testing.T) {
	New(":7777").Serve()
}
