package server

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"github.com/daemon369/go-socks5/address"
	"github.com/daemon369/go-socks5/cmd"
	"github.com/daemon369/go-socks5/cmd/connect"
	"github.com/daemon369/go-socks5/common"
	"github.com/daemon369/go-socks5/server/auth"
)

var logger = log.New(os.Stderr, "Server: ", log.LstdFlags)

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

		session := &session{server: server, serial: serial, clientConn: conn, logger: logger}

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
	logger     *log.Logger
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

		if common.ProtocolVersion != buf[0] {
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

		if common.NoAcceptable == a.Method() {
			err = errors.New(string(serial) + ": choose reject authenticator")
			logger.Printf(err.Error())
			break
		}

		conn.Write([]byte{common.ProtocolVersion, byte(a.Method())})

		break
	}

	if err != nil {
		conn.Write([]byte{common.ProtocolVersion, common.NoAcceptable})
		return err
	}

	/*
	3. authenticate
	*/
	if a.Server(conn, serial) != nil {
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

	var rspCode byte = common.Success

	for {
		if _, err = io.ReadFull(conn, buf[:3]); err != nil {
			rspCode = common.ServerError
			logger.Printf("%d: read cmd & address type failed: %v", serial, err)
			break
		}

		// verify socks protocol version
		if common.ProtocolVersion != buf[0] {
			rspCode = common.ServerError
			err = errors.New(string(serial) + ": unsupported protocol version: " + string(buf[0]))
			logger.Printf(err.Error())
			break
		}

		// verify client request cmd
		command := buf[1]

		if !cmd.VerifyCmd(command) {
			rspCode = common.CommandUnsupported
			err = errors.New(string(serial) + ": unsupported cmd: " + string(command))
			logger.Println(err)
			break
		}

		logger.Printf("%d: cmd: %d", serial, command)

		if 0 != buf[2] {
			err = errors.New(string(serial) + ": reserved byte must be zero: " + string(buf[2]))
			logger.Println(err)
			if session.server.strictMode {
				rspCode = common.ServerError
				break
			}
		}

		var addr *address.Address
		addr, err = address.ReadAddress(conn)
		if err != nil {
			rspCode = common.ServerError
			logger.Printf("%d: read address error: %v", serial, err)
			break
		}

		if addr.Type == address.Unknown {
			rspCode = common.ServerError
			err = errors.New(string(serial) + ": unsupported address type: " + string(addr.Type))
			logger.Printf("%d: read address error: %v", serial, err)
			break
		}

		portStr := strconv.Itoa(int(addr.Port))

		addrFull := net.JoinHostPort(addr.Host, portStr)

		logger.Printf("%d: remote address: %v", serial, addrFull)

		// TODO only support connect for now
		switch command {
		case cmd.CONNECT:
			rspCode, err = connect.Connect(session.clientConn, session.targetConn, session.logger, serial, addrFull)
			if err != nil {
				break
			}

			return nil

		default:
			rspCode = common.ServerError
			err = errors.New(string(serial) + ": unsupported command: " + string(command))
			logger.Printf(err.Error())
			break
		}

		break
	}

	if err != nil {
		conn.Write([]byte{common.ProtocolVersion, rspCode, 0, 1, 0, 0, 0, 0, 0, 0})
		return err
	}

	return nil
}
