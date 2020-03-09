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

package socks5

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"net"
)

var (
	Version = uint8(5)

	ConnectCommand   = uint8(1)
	BindCommand      = uint8(2)
	AssociateCommand = uint8(3)

	ReplyCommandNotSupported = uint8(7)

	IPv4Address = uint8(1)
	FQDNAddress = uint8(3)
	IPv6Address = uint8(4)
)

const (
	NoAuthRequired          uint8 = 0
	UsernameAndPasswordAuth uint8 = 2
)

const (
	SuccessReply uint8 = iota
	ServerFailure
	RuleFailure
	NetworkUnreachable
	HostUnreachable
	ConnectionRefused
	TTLExpired
	CommandNotSupported
	AddrTypeNotSupported
)

type Config struct {
	Logger         *logrus.Entry
	RequestHandler func(*Conn)
}

type Server struct {
	*Config
}

func NewServer(c *Config) (*Server, error) {
	c.Logger.Trace("new server")
	if c.RequestHandler == nil {
		return nil, fmt.Errorf("RequestHandler must be set")
	}
	return &Server{
		Config: c,
	}, nil
}

func (s *Server) ListenAndServe(network, addr string) error {
	s.Logger.Trace("listen and serve")
	l, err := net.Listen(network, addr)
	if err != nil {
		return fmt.Errorf("listen > %w", err)
	}
	s.Logger.Warningf("Listen on %s", addr)

	return s.serve(l)
}

func (s *Server) serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			s.Logger.Errorf("failed to get conn %w", err)
			continue
		}
		s.Logger.Tracef("got conn from %s", conn.RemoteAddr())

		go s.serveConn(&Conn{Conn: conn})
	}
}

func (s *Server) serveConn(conn *Conn) {
	defer conn.Close()
	version := []byte{0}
	if _, err := conn.Read(version); err != nil {
		s.Logger.Errorf("failed to get version byte: %v", err)
		return
	}

	if version[0] != 5 {
		s.Logger.Errorf("unsupported SOCKS version: %v", version)
		return
	}

	if err := s.auth(conn); err != nil {
		s.Logger.Errorf("failed to authenticate: %v", err)
		return
	}

	s.RequestHandler(conn)
}

func (s *Server) auth(conn *Conn) error {
	nmethods := []byte{0}
	_, err := conn.Read(nmethods)
	if err != nil {
		return err
	}

	methods := make([]byte, nmethods[0])
	if _, err = conn.Read(methods); err != nil {
		return err
	}

	return conn.ReplyAuth(NoAuthRequired)
}
