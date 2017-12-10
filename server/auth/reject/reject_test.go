package reject

import (
	"testing"
	"fmt"
)

func Test_reject(t *testing.T) {
	a := Reject{}
	fmt.Println(a.Method())
}

func Test_authenticator(t *testing.T) {
	a := New()
	fmt.Println(a)
}
