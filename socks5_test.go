package go_socks5

import (
	"testing"
	"fmt"
)

func Test_Serve(t *testing.T) {
	server := New(":7777")
	fmt.Println(server)
	t.Log("server started success")
	server.Serve()
}
