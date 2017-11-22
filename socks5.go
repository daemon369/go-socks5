package go_socks5

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	_ "github.com/daemon369/go-socks5/auth/noauth"
	_ "github.com/daemon369/go-socks5/auth/reject"
	"github.com/daemon369/go-socks5/address"
	"github.com/daemon369/go-socks5/auth"
	"github.com/daemon369/go-socks5/cmd"
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
	listener   net.Listener
}

func New(address string) *Server {
	return &Server{address: address, strictMode: false}
}

func (server *Server) String() string {
	return fmt.Sprintf("[address: %v]", server.address)
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

	server.listener = listener

	defer func() { server.Shutdown() }()

	var serial = 0

	for {
		conn, err := listener.Accept()

		if err != nil {
			logger.Println("accept failed: ", err)
			continue
		}

		session := &session{server, serial, conn, nil}

		go handleConnection(session)

		serial++
	}

	logger.Printf("server[%v] shutdown", server)
}

func (server *Server) Shutdown() {
	if server.listener != nil {
		server.listener.Close()
	}
}

func (server *Server) chooseAuthenticator(methods []byte) (a auth.Authenticator) {
	for i := 0; i < len(methods); i++ {
		if a, err := auth.Get(int(methods[i])); err == nil {
			return a
		}
	}

	return nil
}

type session struct {
	server     *Server
	serial     int
	clientConn net.Conn
	targetConn net.Conn
}

func handleConnection(session *session) {
	logger.Printf("%d: connection from %s\n", session.serial, session.clientConn.RemoteAddr().String())

	defer func() {
		err := session.clientConn.Close()
		if err != nil {
			logger.Printf("%d: close client conn : %s", session.serial, err)
		}

		if session.targetConn != nil {
			err = session.targetConn.Close()
			if err != nil {
				logger.Printf("%d: close target conn : %s", session.serial, err)
			}
		}
	}()

	err := handle(session)
	if err != nil {
		logger.Printf("%d: handle: %v", session.serial, err)
		return
	}

}

func handle(session *session) (err error) {

	conn := session.clientConn
	serial := session.serial

	// buf
	var buf []byte

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
			err = errors.New(string(serial) + ": unsupported protocol version")
			logger.Printf(err.Error())
			break
		}

		methodsNum := buf[1]

		if 0 == methodsNum {
			err = errors.New(string(serial) + ": no methods provided")
			logger.Printf(err.Error())
			break
		}

		if _, err = io.ReadFull(conn, buf[:methodsNum]); err != nil {
			logger.Printf("%d: read methods failed: %v", serial, err)
			break
		}

		a = session.server.chooseAuthenticator(buf[:methodsNum])

		if a == nil {
			err = errors.New(string(serial) + ": can't find authenticator")
			logger.Printf(err.Error())
			break
		}

		if auth.NO_ACCEPTABLE == a.Method() {
			err = errors.New(string(serial) + ": choose reject authenticator")
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
		err = errors.New(string(serial) + ": authenticate failed")
		logger.Printf(err.Error())
		return err
	}

	/*
	4. handle client request

	request:
	+----+-----+-------+------+----------+----------+
	|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	+----+-----+-------+------+----------+----------+
	| 1  |  1  | X'00' |  1   | Variable |    2     |
	+----+-----+-------+------+----------+----------+

	response:
	+----+-----+-------+------+----------+----------+
	|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	+----+-----+-------+------+----------+----------+
	| 1  |  1  | X'00' |  1   | Variable |    2     |
	+----+-----+-------+------+----------+----------+
	*/

	var rspCode byte = Success

	// get local host & port
	var localAddrType = address.Unknown
	var localHost = "0.0.0.0"
	var localIp = net.IP{}
	var localPortStr = "0"
	var localPort = 0

	var hostAndPort []byte

	localAddr := conn.LocalAddr()
	if localAddr != nil {
		localHost, localPortStr, err = net.SplitHostPort(conn.LocalAddr().String())

		if err != nil {
			logger.Printf("%d: get local address failed: %v", serial, err)
		} else {

			localAddrType, localHost, localIp, err = address.ParseAddress(localHost)

			if localPort, err = strconv.Atoi(localPortStr); err != nil {
				logger.Printf("%d: parse local address port failed: %v", serial, err)
			}
		}
	} else {
		logger.Printf("%d: can't get local address", serial)
	}

	switch localAddrType {
	case address.IPv4:
		hostAndPort = append(hostAndPort, address.IPv4)
		hostAndPort = append(hostAndPort, localIp...)

	case address.FQDN:
		hostAndPort = append(hostAndPort, address.FQDN)
		hostAndPort = append(hostAndPort, uint8(len(localHost)))
		hostAndPort = append(hostAndPort, localHost...)

	case address.IPv6:
		hostAndPort = append(hostAndPort, address.IPv6)
		hostAndPort = append(hostAndPort, localIp...)

	default:
		hostAndPort = append(hostAndPort, address.IPv4)
		hostAndPort = append(hostAndPort, net.IPv4zero...)
	}

	hostAndPort = append(hostAndPort, byte(localPort>>8), byte(localPort))

	for {
		// read 4 byte to get the address type, and determine length of the address to read next
		if _, err = io.ReadFull(conn, buf[:4]); err != nil {
			rspCode = ServerError
			logger.Printf("%d: read cmd & address type failed: %v", serial, err)
			break
		}

		// verify socks protocol version
		if ProtocolVersion != buf[0] {
			rspCode = ServerError
			err = errors.New(string(serial) + ": unsupported protocol version: " + string(buf[0]))
			logger.Printf(err.Error())
			break
		}

		// verify client request cmd
		command := buf[1]

		if !cmd.VerifyCmd(command) {
			rspCode = CommandUnsupported
			err = errors.New(string(serial) + ": unsupported cmd: " + string(command))
			logger.Println(err)
			break
		}

		logger.Printf("%d: cmd: %d", serial, command)

		if 0 != buf[2] {
			err = errors.New(string(serial) + ": reserved byte must be zero: " + string(buf[2]))
			logger.Println(err)
			if session.server.strictMode {
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
				err = errors.New(string(serial) + ": unsupported address type: " + string(addressType))
			}
			logger.Println(err.Error())
			break
		}

		hostSlice := make([]byte, addressLen)
		host := ""

		if _, err = io.ReadFull(conn, hostSlice); err != nil {
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

		portStr := strconv.Itoa(int(port))

		addr := net.JoinHostPort(host, portStr)

		logger.Printf("%d: remote address: %v", serial, addr)

		// TODO only support connect for now
		switch command {
		case cmd.CONNECT:
			session.targetConn, err = net.Dial("tcp", addr)

			if err != nil {
				rspCode = NetworkUnreachable
				break
			}

			if _, err = conn.Write(append([]byte{ProtocolVersion, 0, 0}, hostAndPort...)); err != nil {
				rspCode = ServerError
				break
			}

			ch := make(chan int, 2)

			go transport(session, conn, session.targetConn, ch)
			go transport(session, session.targetConn, conn, ch)

			<-ch
			<-ch

			logger.Println(serial, ": finish transmission")

			return nil

		default:
			rspCode = ServerError
			err = errors.New(string(serial) + ": unsupported command: " + string(command))
			logger.Printf(err.Error())
			break
		}

		break
	}

	if err != nil {
		conn.Write(append([]byte{ProtocolVersion, rspCode, 0}, hostAndPort...))
		return err
	}

	return nil
}

func transport(session *session, src, dst net.Conn, ch chan int) {
	n, err := io.Copy(src, dst)

	if err != nil {
		logger.Println(err)
	}

	logger.Println(session.serial, ": transported: ", n)

	ch <- 1
}
