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
	"encoding/binary"
	"net"
	"strconv"
)

type Port uint16

func NewPort(p []byte) Port {
	return Port(binary.BigEndian.Uint16(p))
}

func (p Port) Bytes() []byte {
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(p))
	return port
}

type Addr struct {
	ATYP uint8
	FQDN string
	IP   net.IP
	Port Port
}

func (addr *Addr) Address() string {
	if 0 != len(addr.IP) {
		return net.JoinHostPort(addr.IP.String(), strconv.Itoa(int(addr.Port)))
	}
	return net.JoinHostPort(addr.FQDN, strconv.Itoa(int(addr.Port)))
}

func (addr *Addr) Bytes() []byte {
	if addr == nil {
		return []byte{
			IPv4Address,
			0, 0, 0, 0, // IP
			0, 0, // port
		}
	}

	// Format the address
	var body []byte

	switch addr.ATYP {
	case IPv4Address:
		body = addr.IP.To4()
	case FQDNAddress:
		body = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
	case IPv6Address:
		body = addr.IP.To16()
	}

	return append([]byte{addr.ATYP}, append(body, addr.Port.Bytes()...)...)
}
