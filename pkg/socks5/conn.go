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

import "net"

type Conn struct {
	net.Conn
}

func (c *Conn) ReplyAuth(method byte) error {
	_, err := c.Write([]byte{Version, method})
	return err
}

func (c *Conn) ReplyRequest(rep uint8, addr *Addr) error {
	msg := append([]byte{Version, rep, 0}, addr.Bytes()...)
	_, err := c.Write(msg)
	return err
}
