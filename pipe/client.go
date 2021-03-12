// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pipe

import (
	"bufio"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

const Usage = `Usage: %s <public-name>:<public-port> <private-addr>:<private-port> [<private-tls-name>]]
`

func Main(proxyAddr string) (exitCode int) {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), Usage, os.Args[0])
	}

	flag.Parse()

	var (
		src  string
		dest string
		name string
		ok   bool
	)

	switch flag.NArg() {
	case 3:
		name = flag.Arg(2)
		fallthrough

	case 2:
		dest = flag.Arg(1)
		src = flag.Arg(0)
		ok = true
	}

	if !ok {
		flag.Usage()
		return 2
	}

	if err := Client(proxyAddr, src, dest, name); err != nil {
		log.Print(err)
		return 1
	}

	return 0
}

type bufConn struct {
	*bufio.Reader
	io.Writer
}

func Client(proxyAddr, publicAddr, localAddr, localTLSServerName string) error {
	if len(publicAddr) > 255 {
		panic(publicAddr)
	}
	request := make([]byte, 2)
	request[0] = 1 // Protocol version.
	request[1] = byte(len(publicAddr))
	request = append(request, publicAddr...)

	var tlsConfig *tls.Config
	if localTLSServerName != "" {
		tlsConfig = &tls.Config{
			ServerName:         localTLSServerName,
			InsecureSkipVerify: true,
		}
	}

	var i uint64
	for {
		i++
		if err := connect(i, proxyAddr, request, localAddr, tlsConfig); err != nil {
			return err
		}
	}
}

func connect(num uint64, proxyAddr string, request []byte, localAddr string, tlsConfig *tls.Config) error {
	log.Printf("%6d: offering", num)

	proxyConn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return err
	}
	defer func() {
		if proxyConn != nil {
			proxyConn.Close()
		}
	}()

	if _, err := proxyConn.Write(request); err != nil {
		return err
	}

	proxyRead := bufio.NewReader(proxyConn)
	if _, err := proxyRead.ReadByte(); err != nil {
		if err == io.EOF {
			log.Printf("%6d: dropped", num)
			err = nil
		}
		return err
	}
	if err := proxyRead.UnreadByte(); err != nil {
		panic(err)
	}

	local, err := net.Dial("tcp", localAddr)
	if err != nil {
		return err
	}
	defer func() {
		if local != nil {
			local.Close()
		}
	}()

	if tlsConfig != nil {
		local = tls.Client(local, tlsConfig)
	}

	log.Printf("%6d: connected", num)

	go transfer(num, proxyRead, proxyConn.(*net.TCPConn), local.(localConn))
	proxyConn = nil
	local = nil
	return nil
}

type localConn interface {
	io.ReadWriteCloser
	CloseWrite() error
}

func transfer(num uint64, proxyRead io.Reader, proxyConn *net.TCPConn, local localConn) error {
	defer local.Close()
	defer proxyConn.Close()

	done1 := make(chan struct{})
	done2 := make(chan struct{})

	go func() {
		defer close(done1)
		transferUni(num, local, proxyRead, "received")
	}()

	go func() {
		defer close(done2)
		transferUni(num, proxyConn, local, "sent")
	}()

	<-done1
	<-done2

	return nil
}

type closeWriter interface {
	io.Writer
	CloseWrite() error
}

func transferUni(num uint64, w closeWriter, r io.Reader, direction string) {
	defer w.CloseWrite()

	var (
		n   int64
		err = errPanic
	)

	defer func() {
		if err == nil {
			log.Printf("%6d: %s %d bytes", num, direction, n)
		} else {
			log.Printf("%6d: %s %d bytes (%v)", num, direction, n, err)
		}
	}()

	n, err = io.Copy(w, r)
}

var errPanic = errors.New("panic")
