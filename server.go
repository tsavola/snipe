// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snipe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
	"import.name/lock"
)

const (
	publicHandshakeTimeout = time.Second * 5
)

func Server(ctx context.Context, domain string, publicTLS *tls.Config, intraNet, intraAddr string, intraTLS *tls.Config) error {
	defer func() {
		if x := recover(); x != nil {
			Err.Printf("panic: %v", x)
			panic(x)
		}
	}()

	s := &server{
		suffix:    "." + domain,
		publicTLS: publicTLS,
		ports:     make(map[int]map[string]func(*tls.Conn)),
	}
	s.cond.L = &s.mu

	if err := s.serve(ctx, intraNet, intraAddr, intraTLS); err != nil {
		Err.Printf("fatal: %v", err)
		return err
	}

	return nil
}

type server struct {
	suffix    string
	publicTLS *tls.Config

	mu    sync.Mutex
	ports map[int]map[string]func(*tls.Conn)
	cond  sync.Cond
}

func (s *server) serve(ctx context.Context, intraNet, intraAddr string, intraTLS *tls.Config) error {
	l, err := net.Listen(intraNet, intraAddr)
	if err != nil {
		return err
	}
	defer l.Close()

	var done uint32
	go func() {
		<-ctx.Done()
		atomic.StoreUint32(&done, 1)
		l.Close()
	}()

	Info.Printf("running")
	defer Info.Printf("shutdown")
	defer daemon.SdNotify(false, daemon.SdNotifyStopping)

	if _, err := daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
		return err
	}

	for {
		private, err := l.Accept()
		if err != nil {
			if errors.Is(err, context.Canceled) || atomic.LoadUint32(&done) == 1 {
				err = nil
			}
			return err
		}

		Info.Printf("accepted private connection")

		if intraTLS != nil {
			private = tls.Server(private, intraTLS)
		}

		go func() {
			if err := s.handle(private.(intraConn)); err != nil {
				Err.Printf("handle: %v", err)
			}
		}()
	}
}

type intraConn interface {
	net.Conn
	CloseWrite() error
}

func (s *server) handle(private intraConn) error {
	closePrivate := true
	defer func() {
		if closePrivate {
			private.Close()
		}
	}()

	b := make([]byte, 1)
	if _, err := io.ReadFull(private, b); err != nil {
		return err
	}
	if version := b[0]; version != 1 {
		return fmt.Errorf("unsupported protocol version: %d", version)
	}

	if _, err := io.ReadFull(private, b); err != nil {
		return err
	}
	addrSize := b[0]

	b = make([]byte, addrSize)
	if _, err := io.ReadFull(private, b); err != nil {
		return err
	}
	addr := string(b)

	name, portstr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	name = name + s.suffix

	n, err := strconv.ParseUint(portstr, 10, 16)
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("port 0 not supported")
	}
	port := int(n)

	var (
		newFunc = func(public *tls.Conn) { transfer(private, public) }
		oldFunc func(*tls.Conn)
	)

	lock.Guard(&s.mu, func() {
		names := s.ports[port]
		if names == nil {
			names = make(map[string]func(*tls.Conn))

			err = s.listen(port, names)
			if err != nil {
				return
			}

			s.ports[port] = names
		}

		oldFunc = names[name]
		names[name] = newFunc
		Info.Printf("private connection available: %s:%d", name, port)
		s.cond.Broadcast()
	})
	if err != nil {
		return err
	}

	closePrivate = false

	if oldFunc != nil {
		oldFunc(nil) // Close superseded connection.
	}

	return nil
}

func (s *server) listen(port int, names map[string]func(*tls.Conn)) error {
	c := s.publicTLS.Clone()
	if port == 443 {
		c.NextProtos = append([]string{"http/1.1"}, c.NextProtos...)
	} else {
		c.NextProtos = nil
	}

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}

	if len(c.NextProtos) == 0 {
		Info.Printf("listening at public port %d (no ALPN)", port)
	} else {
		Info.Printf("listening at public port %d (%s)", port, strings.Join(c.NextProtos, " "))
	}

	go s.listenLoop(port, l, names)
	return nil
}

func (s *server) listenLoop(port int, l net.Listener, names map[string]func(*tls.Conn)) {
	defer l.Close()

	for {
		public, err := l.Accept()
		if err != nil {
			Err.Printf("accept: %v", err)
			return
		}

		Info.Printf("public connection to port %d accepted from %s", port, public.RemoteAddr())

		go s.forward(port, public.(*tls.Conn), names)
	}
}

func (s *server) forward(port int, public *tls.Conn, names map[string]func(*tls.Conn)) {
	defer public.Close()

	if err := public.SetDeadline(time.Now().Add(publicHandshakeTimeout)); err != nil {
		panic(err)
	}

	if err := public.Handshake(); err != nil {
		Info.Printf("public port %d handshake: %v", port, err)
		return
	}

	name := public.ConnectionState().ServerName

	if err := public.SetDeadline(time.Time{}); err != nil {
		panic(err)
	}

	var f func(*tls.Conn)

	lock.Guard(&s.mu, func() {
		for {
			f = names[name]
			if f != nil {
				delete(names, name)
				break
			}
			Info.Printf("waiting for private connection: %s:%d", name, port)
			s.cond.Wait()
		}
	})

	Info.Printf("public connection attached to private connection: %s:%d", name, port)
	f(public)
}

// transfer data bidirectionally unless public connection is nil.  Private
// connection will be closed in any case.
func transfer(private intraConn, public *tls.Conn) {
	defer private.Close()

	if public == nil {
		return
	}

	done1 := make(chan struct{})
	done2 := make(chan struct{})

	go func() {
		defer close(done1)
		defer private.CloseWrite()
		io.Copy(private, public)
	}()

	go func() {
		defer close(done2)
		defer public.CloseWrite()
		io.Copy(public, private)
	}()

	<-done1
	<-done2
}
