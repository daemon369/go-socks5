package socks5

import (
	"net"
	"log"
	"os"
	e "errors"
	"github.com/daemon369/go-socks5/auth/auth"
)

var logger = log.New(os.Stderr, "Socks5: ", log.LstdFlags)

type Server struct {
	address string
}

func New(address string) *Server {
	return &Server{address}
}

func Serve(server Server) {
	server.Serve()
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

	// buffer
	ver := make([]byte, 257)
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
		n, err = conn.Read(ver)
		if err != nil {
			logger.Printf("%d: read protocol version failed: %s", serial, err)
			break
		}

		logger.Printf("%d: protocol verison: %v", serial, ver[0])

		if 5 != ver[0] {
			logger.Printf("%d: unsupported protocol version", serial)
			err = e.New(string(serial) + ": unsupported protocol version")
			break
		}

		if n < 3 || ver[1] == 0 {
			logger.Printf("%d: no methods provided", serial)
			err = e.New(string(serial) + ": no methods provided")
			break
		}

		if int(ver[1]) != n-2 {
			logger.Printf("%d: number of methods(%d) not match methods length(%d)", serial, ver[1], n-2)
		}

		a = server.chooseAuthenticator(ver[2:n])

		if a == nil {
			logger.Printf("%d: can't find authenticator", serial)
			err = e.New(string(serial) + ": can't find authenticator")
			break
		}

		if a.Method() == 0xff {
			logger.Printf("%d: choose reject authenticator", serial)
			err = e.New(string(serial) + ": choose reject authenticator")
			break
		}

		conn.Write([]byte{0x05, byte(a.Method())})

		n, err = conn.Read(ver)

		if err != nil {

		}

		if a.Authenticate(conn, serial) != nil {
			logger.Printf("%d: authenticate failed", serial)
			err = e.New("authenticate failed")
			break
		}

		break
	}

	if err != nil {
		conn.Write([]byte{0x05, 0xff})
		return err
	}

	return nil
}
