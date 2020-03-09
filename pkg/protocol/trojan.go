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

package protocol

import (
	"crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"errors"
	"github.com/saito-mayumi/trojan-go/pkg/socks5"
)

var OtherProtocol = errors.New("other protocol")

type Request struct {
	PasswordHex []byte
	Cmd         uint8
	Addr        socks5.Addr
}

func (r *Request) Bytes() []byte {
	data := make([]byte, 0, 128)
	data = append(data, r.PasswordHex...)
	data = append(data, '\n', r.Cmd, r.Addr.ATYP)

	if r.Addr.ATYP == socks5.IPv4Address {
		data = append(data, r.Addr.IP.To4()...)
	} else if r.Addr.ATYP == socks5.IPv6Address {
		data = append(data, r.Addr.IP.To16()...)
	} else if r.Addr.ATYP == socks5.FQDNAddress {
		data = append(data, append([]byte{byte(len(r.Addr.FQDN))}, []byte(r.Addr.FQDN)...)...)
	}

	return append(data, append(r.Addr.Port.Bytes(), '\n')...)
}

type Authenticator interface {
	Authenticate([]byte) bool
}

type AuthenticatorFunc func([]byte) bool

func (f AuthenticatorFunc) Authenticate(pass []byte) bool {
	return f(pass)
}

func HashPass(pass []byte) []byte {
	h := sha256.New224()
	h.Write(pass)
	return h.Sum(nil)
}

func PassHashAndHex(pass []byte) []byte {
	hexed := make([]byte, 56)
	hex.Encode(hexed, HashPass(pass))
	return hexed
}
