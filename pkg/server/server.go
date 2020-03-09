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
	"fmt"
	"github.com/saito-mayumi/trojan-go/pkg/protocol"
	"github.com/saito-mayumi/trojan-go/pkg/socks5"
	"io"
	"log"
	"net"
	"strings"
)

type Server struct {
	authenticator protocol.Authenticator
}

func NewServer(authenticator protocol.Authenticator) (*Server, error) {
	return &Server{
		authenticator: authenticator,
	}, nil
}

func (s *Server) NewListener(ln net.Listener) *Listener {
	return &Listener{
		Listener: ln,
		Server:   s,
	}
}

func (s *Server) handleConn(clientConn net.Conn) error {
	reqMsg := make([]byte, 128)
	passHash := reqMsg[:56]

	_, err := clientConn.Read(passHash)
	if err != nil {
		return protocol.OtherProtocol
	}

	if !s.authenticator.Authenticate(passHash) {
		// fixme
		fmt.Println("incorrect password")
		return protocol.OtherProtocol
	}

	fmt.Println("password")

	_, err = clientConn.Read(reqMsg[56:60])
	if err != nil {
		// fixme
		fmt.Println("failed to read protocol")
		return protocol.OtherProtocol
	}

	cmd := reqMsg[58]
	atype := reqMsg[59]

	addr := &socks5.Addr{
		ATYP: atype,
	}

	switch atype {
	case socks5.IPv4Address:
		ipAndPort := reqMsg[60:66]
		clientConn.Read(ipAndPort)
		addr.IP = net.IPv4(ipAndPort[0], ipAndPort[1], ipAndPort[2], ipAndPort[3])
		addr.Port = socks5.NewPort(ipAndPort[4:6])

	case socks5.FQDNAddress:
		lengthMsg := reqMsg[60:61]
		clientConn.Read(lengthMsg)
		length := lengthMsg[0]

		if lack := length - (128 - 61 - 2); lack > 0 {
			reqMsg = append(reqMsg, make([]byte, lack)...)
		}

		domainAndPort := reqMsg[61 : 61+length+2]
		addrBody := domainAndPort[:length]
		port := domainAndPort[length:]
		clientConn.Read(domainAndPort)

		addr.FQDN = string(addrBody)
		addr.Port = socks5.NewPort(port)

	case socks5.IPv6Address:
		ipAndPort := reqMsg[60:78]
		clientConn.Read(ipAndPort)
		addr.IP = ipAndPort[:16]
		addr.Port = socks5.NewPort(ipAndPort[17:19])
	}


	if cmd == socks5.ConnectCommand {
		conn, err := net.Dial("tcp", addr.Address())
		if err != nil {
			log.Println("could not connect to %s", addr.Address())

			msg := err.Error()
			resp := socks5.HostUnreachable
			if strings.Contains(msg, "refused") {
				resp = socks5.ConnectionRefused
			} else if strings.Contains(msg, "network is unreachable") {
				resp = socks5.NetworkUnreachable
			}
			_ = resp
			return protocol.OtherProtocol
		}
		log.Println("connected to dest:", conn.RemoteAddr())

		crlf := make([]byte, 2)
		clientConn.Read(crlf)

		go proxy(clientConn, conn)
		proxy(conn, clientConn)
	} else if cmd == socks5.AssociateCommand {
		log.Fatal("fix me")
	} else if cmd == socks5.BindCommand {
		return protocol.OtherProtocol
	}
	return nil
}

func proxy(dst io.Writer, src io.Reader) error {
	_, err := io.Copy(dst, src)
	return err
}
