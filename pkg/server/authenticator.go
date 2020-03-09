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
	"github.com/saito-mayumi/trojan-go/pkg/protocol"
)

func NewDefaultAuthenticator(passwordList []string) protocol.Authenticator {
	hexedPasswords := make([][]byte, len(passwordList))
	for i, pass := range passwordList {
		hexedPasswords[i] = protocol.PassHashAndHex([]byte(pass))
	}
	return protocol.AuthenticatorFunc(func(target []byte) bool {
		for _, pass := range hexedPasswords {
			if 0 == bytes.Compare(pass, target) {
				return true
			}
		}
		return false
	})
}
