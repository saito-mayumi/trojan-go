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
	"errors"
	"io"
)

type limitedReader struct {
	r io.Reader
	max int
	cur int
}

func (r *limitedReader) Read(b []byte) (n int, err error) {
	if r.cur >= r.max {
		return 0, io.EOF
	}

	n, err = r.r.Read(b)
	if err != nil {
		return
	}
	r.cur += n
	return
}


func newBackupReader(r, backup io.Reader) *backupReader {
	return &backupReader{
		r:      r,
		backup: backup,
		cur:    r,
	}
}

type backupReader struct {
	r io.Reader
	backup io.Reader
	cur io.Reader
}

func (r *backupReader) Read(b []byte) (n int, err error) {
	n, err = r.cur.Read(b)
	if err == nil {
		return
	}
	if errors.Is(err, io.EOF) {
		if r.cur == r.backup {
			return
		}
		r.cur = r.backup
	}

	return r.cur.Read(b)
}
