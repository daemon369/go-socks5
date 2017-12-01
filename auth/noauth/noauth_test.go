package noauth

import (
	"testing"
	"fmt"
)

func Test_noauth(t *testing.T) {
	a := NoAuth{}
	fmt.Println(a.Method())
}
