package go_socks5

import (
	"net"
	"log"
	"os"
	e "errors"
	_ "github.com/daemon369/go-socks5/auth/noauth"
	_ "github.com/daemon369/go-socks5/auth/reject"
	"github.com/daemon369/go-socks5/auth"
	"github.com/daemon369/go-socks5/cmd"
	"github.com/daemon369/go-socks5/address"
)

const (
	PROTOCOL_VERSION = 0x05
)

var logger = log.New(os.Stderr, "Socks5: ", log.LstdFlags)

type Server struct {
	// server listen address
	address string
	// strict mode flag
	strictMode bool
}

func New(address string) *Server {
	return &Server{address, false}
}

func Serve(server Server) {
	server.Serve()
}

func (s *Server) SetStrictMode(strict bool) {
	s.strictMode = strict
}

func (s *Server) GetStrictMode() bool {
	return s.strictMode
}

func (server *Server) Serve() {

	logger.Printf("Serves at %s", server.address)

	listener, err := net.Listen("tcp", server.address)

	if err != nil {
		logger.Printf("listener failed: %v", err)
		return
	}

	var serial = 0

	for {
		conn, err := listener.Accept()

		if err != nil {
			logger.Println("accept failed: ", err)
			return
		}

		go handleConnection(server, conn, serial)

		serial++
	}

	if err != nil {
		//logger.Println("connect failed")
		return
	}

	//logger.Println("connect success")

}

func (server *Server) chooseAuthenticator(methods []byte) (a auth.Authenticator) {
	for i := 0; i < len(methods); i++ {
		if a, err := auth.Get(int(methods[i])); err == nil {
			return a
		}
	}

	return nil
}

func handleConnection(server *Server, conn net.Conn, serial int) {
	logger.Printf("%d: connection from %s\n", serial, conn.RemoteAddr().String())

	defer func() {
		err := conn.Close()
		if err != nil {
			logger.Printf("%d: close conn : %s", serial, err)
		}
	}()

	err := handle(server, conn, serial)
	if err != nil {
		logger.Printf("%d: handle: %v", serial, err)
		return
	}

}

func handle(server *Server, conn net.Conn, serial int) (err error) {

	// read length
	var n = 0

	var a auth.Authenticator

	/*
	1. handle the version identifier/method selection message from client
	+----+----------+----------+
	|VER | NMETHODS | METHODS  |
	+----+----------+----------+
	| 1  |    1     | 1 to 255 |
	+----+----------+----------+
	*/

	/*
	2. select a method from METHODS, and sends a METHOD selection message to client
	+----+--------+
	|VER | METHOD |
	+----+--------+
	| 1  |   1    |
	+----+--------+
	*/

	for {
		// buffer
		buf := make([]byte, 257)

		n, err = conn.Read(buf)
		if err != nil {
			logger.Printf("%d: read protocol version failed: %s", serial, err)
			break
		}

		logger.Printf("%d: protocol verison: %v", serial, buf[0])

		if PROTOCOL_VERSION != buf[0] {
			logger.Printf("%d: unsupported protocol version", serial)
			err = e.New(string(serial) + ": unsupported protocol version")
			break
		}

		if n < 3 || buf[1] == 0 {
			logger.Printf("%d: no methods provided", serial)
			err = e.New(string(serial) + ": no methods provided")
			break
		}

		if int(buf[1]) != n-2 {
			logger.Printf("%d: number of methods(%d) not match methods length(%d)", serial, buf[1], n-2)
		}

		a = server.chooseAuthenticator(buf[2:n])

		if a == nil {
			logger.Printf("%d: can't find authenticator", serial)
			err = e.New(string(serial) + ": can't find authenticator")
			break
		}

		if auth.NO_ACCEPTABLE == a.Method() {
			logger.Printf("%d: choose reject authenticator", serial)
			err = e.New(string(serial) + ": choose reject authenticator")
			break
		}

		conn.Write([]byte{PROTOCOL_VERSION, byte(a.Method())})

		break
	}

	if err != nil {
		conn.Write([]byte{PROTOCOL_VERSION, 0xff})
		return err
	}

	/*
	3. authenticate user
	*/
	if a.Authenticate(conn, serial) != nil {
		logger.Printf("%d: authenticate failed", serial)
		return e.New(string(serial) + ": authenticate failed")
	}

	/*
	4. handle client request
	+----+-----+-------+------+----------+----------+
	|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	+----+-----+-------+------+----------+----------+
	| 1  |  1  | X'00' |  1   | Variable |    2     |
	+----+-----+-------+------+----------+----------+
	*/
	// buffer
	buf := make([]byte, 4)
	n, err = conn.Read(buf)

	if err != nil {
		logger.Printf("%d: read client request failed: %v", serial, err)
		return err
	}

	if PROTOCOL_VERSION != buf[0] {
		logger.Printf("%d: unsupported protocol version", serial)
		return e.New(string(serial) + ": unsupported protocol version: " + string(buf[0]))
	}

	if !cmd.VerifyCmd(buf[1]) {
		err = e.New(string(serial) + ": unsupported cmd: " + string(buf[1]))
		logger.Println(err)
		return err
	}

	logger.Printf("%d: cmd: %d", serial, buf[1])

	if 0 != buf[2] {
		err = e.New(string(serial) + ": reserved byte must be zero: " + string(buf[2]))
		logger.Println(err)
		if server.strictMode {
			return err
		}
	}

	var addressType = buf[3]

	switch (addressType) {
	case address.IPV4:
		n, err = conn.Read(buf)
		if err != nil {
			logger.Printf("%d: read IPV4 address error", serial)
			return err
		}
		if n != 4 {
			err = e.New(string(serial) + ": read IPV4 address error")
			logger.Println(err)
			return err
		}

	case address.FQDN:

	case address.IPV6:
		buf = make([]byte, 16)
		n, err = conn.Read(buf)
		if err != nil {
			logger.Printf("%d: read IPV6 address error", serial)
			return err
		}
		if n != 16 {
			err = e.New(string(serial) + ": read IPV6 address error")
			logger.Println(err)
			return err
		}
	default:
		err = e.New(string(serial) + ": unsupported cmd: " + string(buf[1]))
		logger.Println(err)
		return err
	}

	return nil
}
