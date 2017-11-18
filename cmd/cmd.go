package cmd

const (
	CONNECT = 0x01
	BIND    = 0x02
	UDP     = 0x03
)

func VerifyCmd(cmd byte) bool {
	return CONNECT == cmd || BIND == cmd || UDP == cmd
}
