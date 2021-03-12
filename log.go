// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snipe

import (
	"fmt"
	"log/syslog"
)

type Logger interface {
	Printf(string, ...interface{})
}

var (
	Err  Logger
	Info Logger
)

func init() {
	w, err := syslog.Dial("unixgram", "/dev/log", syslog.LOG_DAEMON, "snipe")
	if err != nil {
		panic(err)
	}

	Err = errLogger{w}
	Info = infoLogger{w}
}

type errLogger struct{ *syslog.Writer }
type infoLogger struct{ *syslog.Writer }

func (l errLogger) Printf(f string, a ...interface{})  { l.Err(fmt.Sprintf(f, a...)) }
func (l infoLogger) Printf(f string, a ...interface{}) { l.Info(fmt.Sprintf(f, a...)) }
