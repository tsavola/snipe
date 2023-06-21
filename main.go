// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snipe

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func Main(domain string, publicTLS *tls.Config, intraNet, intraAddr string, intraTLS *tls.Config) (exitCode int) {
	flag.Parse()
	if flag.NArg() != 0 {
		flag.Usage()
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()

	if err := Server(ctx, domain, publicTLS, intraNet, intraAddr, intraTLS); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	return 0
}
