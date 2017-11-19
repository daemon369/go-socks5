package go_socks5

import (
	"net"
	"log"
	"os"
	"io"
	e "errors"
	_ "github.com/daemon369/go-socks5/auth/noauth"
	_ "github.com/daemon369/go-socks5/auth/reject"
	"github.com/daemon369/go-socks5/auth"
	"github.com/daemon369/go-socks5/cmd"
	"github.com/daemon369/go-socks5/address"
	"strconv"
)

const (
	ProtocolVersion = 0x05
)

const (
	Success                = 0x00
	ServerError            = 0x01
	RefusedByRuleSet       = 0x02
	NetworkUnreachable     = 0x03
	HostUnreachable        = 0x04
	ConnectionRefused      = 0x05
	TTLTimeOut             = 0x06
	CommandUnsupported     = 0x07
	AddressTypeUnsupported = 0x08
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

func (server *Server) SetStrictMode(strict bool) {
	server.strictMode = strict
}

func (server *Server) GetStrictMode() bool {
	return server.strictMode
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

	// buf
	var buf []byte

	var n int

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
		buf = make([]byte, 255)

		if _, err = io.ReadFull(conn, buf[:2]); err != nil {
			logger.Printf("%d: read protocol version & methods number failed: %v", serial, err)
			break
		}

		logger.Printf("%d: protocol verison: %v, methods number: %v", serial, buf[0], buf[1])

		if ProtocolVersion != buf[0] {
			err = e.New(string(serial) + ": unsupported protocol version")
			logger.Printf(err.Error())
			break
		}

		methodsNum := buf[1]

		if 0 == methodsNum {
			err = e.New(string(serial) + ": no methods provided")
			logger.Printf(err.Error())
			break
		}

		if _, err = io.ReadFull(conn, buf[:methodsNum]); err != nil {
			logger.Printf("%d: read methods failed: %v", serial, err)
			break
		}

		a = server.chooseAuthenticator(buf[:methodsNum])

		if a == nil {
			err = e.New(string(serial) + ": can't find authenticator")
			logger.Printf(err.Error())
			break
		}

		if auth.NO_ACCEPTABLE == a.Method() {
			err = e.New(string(serial) + ": choose reject authenticator")
			logger.Printf(err.Error())
			break
		}

		conn.Write([]byte{ProtocolVersion, byte(a.Method())})

		break
	}

	if err != nil {
		conn.Write([]byte{ProtocolVersion, auth.NO_ACCEPTABLE})
		return err
	}

	/*
	3. authenticate
	*/
	if a.Authenticate(conn, serial) != nil {
		err = e.New(string(serial) + ": authenticate failed")
		logger.Printf(err.Error())
		return err
	}

	/*
	4. handle client request
	+----+-----+-------+------+----------+----------+
	|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	+----+-----+-------+------+----------+----------+
	| 1  |  1  | X'00' |  1   | Variable |    2     |
	+----+-----+-------+------+----------+----------+
	*/

	var rspCode byte = Success

	for {
		if _, err = io.ReadFull(conn, buf[:4]); err != nil {
			rspCode = ServerError
			logger.Printf("%d: read cmd & address type failed: %v", serial, err)
			break
		}

		if ProtocolVersion != buf[0] {
			rspCode = ServerError
			err = e.New(string(serial) + ": unsupported protocol version: " + string(buf[0]))
			logger.Printf(err.Error())
			break
		}

		// verify client request cmd
		command := buf[1]

		if !cmd.VerifyCmd(command) {
			rspCode = CommandUnsupported
			err = e.New(string(serial) + ": unsupported cmd: " + string(command))
			logger.Println(err)
			break
		}

		logger.Printf("%d: cmd: %d", serial, command)

		if 0 != buf[2] {
			err = e.New(string(serial) + ": reserved byte must be zero: " + string(buf[2]))
			logger.Println(err)
			if server.strictMode {
				rspCode = ServerError
				break
			}
		}

		var addressType = buf[3]
		var addressLen byte = 0

		switch addressType {
		case address.IPv4:
			addressLen = net.IPv4len

		case address.FQDN:
			if _, err = io.ReadFull(conn, buf[:1]); err != nil {
				addressType = address.Unknown
				logger.Printf("%d: read FQDN address length error: %v", serial, err)
				break
			}
			addressLen = buf[0]

		case address.IPv6:
			addressLen = net.IPv6len
		}

		if !address.Support(addressType) {
			rspCode = AddressTypeUnsupported
			if err == nil {
				err = e.New(string(serial) + ": unsupported address type: " + string(addressType))
			}
			logger.Println(err.Error())
			break
		}

		hostSlice := make([]byte, addressLen)
		host := ""

		if n, err = io.ReadFull(conn, hostSlice); err != nil {
			rspCode = ServerError
			logger.Printf("%d: read address[%d] error: %v", serial, addressType, err)
			break
		}

		switch addressType {
		case address.IPv4, address.IPv6:
			host = net.IP(hostSlice).String()
		case address.FQDN:
			host = string(hostSlice)
		}

		if _, err = io.ReadFull(conn, buf[:2]); err != nil {
			rspCode = ServerError
			logger.Printf("%d: read port error: %v", serial, err)
			break
		}

		port := uint16(buf[0])<<8 | uint16(buf[1])

		if port <= 0 || port > 0xFFFF {
			rspCode = HostUnreachable
			err = e.New(string(serial) + ": port number out of range: " + string(port))
			break
		}

		portStr := strconv.Itoa(int(port))

		addr := net.JoinHostPort(host, portStr)

		logger.Printf("%d: remote address: %v", serial, addr)

		break
	}

	if err != nil {
		conn.Write([]byte{ProtocolVersion, rspCode, auth.NO_ACCEPTABLE})
		return err
	}

	logger.Println(n)

	return nil
}
