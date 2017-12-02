package cipher

type Cipher interface {
	Encrypt(src []byte) (data []byte, err error)
	Decrypt(src []byte) (data []byte, err error)
}
