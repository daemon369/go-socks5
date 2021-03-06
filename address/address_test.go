package address

import (
	"testing"
	"fmt"
	"net"
)

func Test_parse(t *testing.T) {

	type testCase struct {
		host   string
		expect bool
	}

	var addrList []testCase
	addrList = append(addrList, testCase{"www.baidu.com", true})
	addrList = append(addrList, testCase{"1.2.3.4", true})
	addrList = append(addrList, testCase{"::ffff:c000:0280", true})
	//addrList = append(addrList, testCase{"9999", false})
	addrList = append(addrList, testCase{"www.meizu.com", true})
	addrList = append(addrList, testCase{"localhost", true})

	for _, v := range addrList {
		addr, err := ParseAddress(v.host)

		fmt.Println(addr, err)

		var ret = false

		if err == nil {
			switch addr.Type {
			case IPv4:
				ip4 := addr.Ip.To4()
				ret = ip4 != nil && len(ip4) == net.IPv4len

			case FQDN:
				ret = len(addr.Host) > 0 && len(addr.Host) < 256

			case IPv6:
				ip6 := addr.Ip.To16()
				ret = ip6 != nil && len(ip6) == net.IPv6len

			default:
				ret = false
			}
		}

		if ret == v.expect {
			t.Log("success")
		} else {
			t.Error("failed")
		}

		fmt.Println()
	}

}
