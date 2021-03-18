// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snipe

import (
	"fmt"
	"log/syslog"

	"github.com/coreos/go-systemd/v22/journal"
)

type Logger interface {
	Printf(string, ...interface{})
}

var (
	Err  Logger
	Info Logger
)

func init() {
	if journal.Enabled() {
		Err = errJournal{}
		Info = infoJournal{}

		Info.Printf("logging to journal")
	} else {
		w, err := syslog.Dial("unixgram", "/dev/log", syslog.LOG_DAEMON, "snipe")
		if err != nil {
			panic(err)
		}

		Err = errLogger{w}
		Info = infoLogger{w}

		Info.Printf("logging to syslog")
	}
}

type errJournal struct{}
type infoJournal struct{}

func (errJournal) Printf(f string, a ...interface{})  { journal.Print(journal.PriErr, f, a...) }
func (infoJournal) Printf(f string, a ...interface{}) { journal.Print(journal.PriInfo, f, a...) }

type errLogger struct{ *syslog.Writer }
type infoLogger struct{ *syslog.Writer }

func (l errLogger) Printf(f string, a ...interface{})  { l.Err(fmt.Sprintf(f, a...)) }
func (l infoLogger) Printf(f string, a ...interface{}) { l.Info(fmt.Sprintf(f, a...)) }
