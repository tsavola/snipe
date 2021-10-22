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
	"strings"
	"time"
)

const Usage = `Usage: %s <public-name>[:<port>] <private-addr>[:<port>] [<private-tls-name>]]

Ports default to 443.  When a port is not specified with the private
address, the private TLS name defaults to the private address.

`

func Main(proxyAddr string, proxyTLS *tls.Config) (exitCode int) {
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

	if !strings.Contains(src, ":") {
		src += ":443"
	}

	if _, _, err := net.SplitHostPort(dest); err != nil {
		d := dest + ":443"
		if _, _, err := net.SplitHostPort(d); err == nil {
			if name == "" {
				name = dest
			}
			dest = d
		}
	}

	if err := Client(proxyAddr, proxyTLS, src, dest, name); err != nil {
		log.Print(err)
		return 1
	}

	return 0
}

type bufConn struct {
	*bufio.Reader
	io.Writer
}

func Client(proxyAddr string, proxyTLS *tls.Config, publicAddr, localAddr, localTLSServerName string) error {
	if len(publicAddr) > 255 {
		panic(publicAddr)
	}
	request := make([]byte, 2)
	request[0] = 1 // Protocol version.
	request[1] = byte(len(publicAddr))
	request = append(request, publicAddr...)

	var localTLS *tls.Config
	if localTLSServerName != "" {
		localTLS = &tls.Config{
			ServerName:         localTLSServerName,
			InsecureSkipVerify: true,
		}
	}

	var i uint64
	for {
		i++
		if err := connect(i, proxyAddr, proxyTLS, request, localAddr, localTLS); err != nil {
			return err
		}
	}
}

const offerTimeout = time.Second * 45

func connect(num uint64, proxyAddr string, proxyTLS *tls.Config, request []byte, localAddr string, localTLS *tls.Config) error {
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

	if proxyTLS != nil {
		proxyConn = tls.Client(proxyConn, proxyTLS)
	}

	if err := proxyConn.SetDeadline(time.Now().Add(offerTimeout)); err != nil {
		panic(err)
	}

	if _, err := proxyConn.Write(request); err != nil {
		return err
	}

	proxyRead := bufio.NewReader(proxyConn)
	if _, err := proxyRead.ReadByte(); err != nil {
		switch {
		case err == io.EOF:
			log.Printf("%6d: dropped", num)
			err = nil
		case errors.Is(err, os.ErrDeadlineExceeded):
			log.Printf("%6d: timed out", num)
			err = nil
		}
		return err
	}

	go func(proxyConn net.Conn) {
		defer proxyConn.Close()

		if err := proxyRead.UnreadByte(); err != nil {
			panic(err)
		}

		local, err := net.Dial("tcp", localAddr)
		if err != nil {
			log.Printf("%6d: error: %v", num, err)
			return
		}
		if localTLS != nil {
			local = tls.Client(local, localTLS)
		}
		defer local.Close()

		log.Printf("%6d: connected", num)

		transfer(num, proxyRead, proxyConn.(conn), local.(conn))
	}(proxyConn)
	proxyConn = nil
	return nil
}

type conn interface {
	io.ReadWriteCloser
	CloseWrite() error
}

func transfer(num uint64, proxyRead io.Reader, proxyConn, local conn) error {
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
