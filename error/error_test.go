package error

import (
	"testing"
	"fmt"
)

func Test_err(t *testing.T) {
	fmt.Println(New("test error"))
}
