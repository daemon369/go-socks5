package connect

import (
	"io"
	"log"
	"net"
	"github.com/daemon369/go-socks5/address"
	"github.com/daemon369/go-socks5/common"
)

func Connect(clientConn, targetConn net.Conn, logger *log.Logger, serial int, addr string) (rspCode byte, err error) {
	targetConn, err = net.Dial("tcp", addr)

	if err != nil {
		rspCode = common.NetworkUnreachable
		return rspCode, err
	}

	defer targetConn.Close()

	if _, err = clientConn.Write(append([]byte{common.ProtocolVersion, 0, 0}, address.FromAddr(targetConn.LocalAddr())...)); err != nil {
		rspCode = common.ServerError
		return rspCode, err
	}

	ch := make(chan int, 2)

	go transport(logger, serial, clientConn, targetConn, ch)
	go transport(logger, serial, targetConn, clientConn, ch)

	<-ch
	<-ch

	logger.Println(serial, ": finish transmission")

	return common.Success, nil
}

func transport(logger *log.Logger, serial int, src, dst net.Conn, ch chan int) {
	n, err := io.Copy(src, dst)

	if err != nil {
		logger.Println(err)
	}

	logger.Println(serial, ": transported: ", n)

	ch <- 1
}
