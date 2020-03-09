/*
 * Trojan-Go is a Golang version of Trojan,
 * which is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2020 github.com://saito-mayumi
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package server

import (
	"bytes"
	"errors"
	"github.com/saito-mayumi/trojan-go/pkg/protocol"
	"io"
	"net"
)

type Listener struct {
	net.Listener
	Server *Server
}

func (ln *Listener) Accept() (net.Conn, error){
	conn, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}

	c := ln.newConn(conn)
	go c.trojanHandler()

	return c, nil
}

func (ln *Listener) newConn(c net.Conn) *Conn {
	return &Conn{
		Conn: c,
		validatingChan: make(chan struct{}),
		server: ln.Server,
	}
}

type Conn struct {
	net.Conn

	server *Server
	isOtherProtocol bool
	validatingChan  chan struct{}
	upstreamReader  io.Reader
}

func (c *Conn) trojanHandler() {
	buf := new(bytes.Buffer)
	c.upstreamReader = newBackupReader(buf, c.Conn)
	reader := io.TeeReader(c.Conn, buf)

	tc := &trojanConn{Conn: c.Conn, r: newBackupReader(&limitedReader{
		r: reader,
		max: 512,
	}, c.Conn)}

	err := c.server.handleConn(tc)
	if errors.Is(err, protocol.OtherProtocol) {
		c.isOtherProtocol = true
	}
	close(c.validatingChan)
}

func (c *Conn) Read(b []byte) (n int, err error) {
	<-c.validatingChan

	if c.isOtherProtocol {
		return c.upstreamReader.Read(b)
	}

	return 0, nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	<-c.validatingChan
	if c.isOtherProtocol {
		return c.Conn.Write(b)
	}
	return 0, nil
}


func (c *Conn) Close() error {
	<-c.validatingChan
	if c.isOtherProtocol {
		return c.Conn.Close()
	}

	return nil
}

type trojanConn struct {
	net.Conn
	r io.Reader
}

func (tc *trojanConn) Read(b []byte) (n int, err error) {
	return tc.r.Read(b)
}

