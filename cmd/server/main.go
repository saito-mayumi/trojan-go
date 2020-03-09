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

package main

import (
	"crypto/tls"
	"fmt"
	"github.com/saito-mayumi/trojan-go/pkg/server"
	"net/http"
)

func main() {
	fmt.Println(`Trojan-Go  Copyright (C) 2020  github.com://saito-mayumi
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it.`)

	authenticator := server.NewDefaultAuthenticator([]string{"password1", "password2"})
	s, err := server.NewServer(authenticator)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Passwords: %s", "password1, password2\n")

	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		panic(err)
	}

	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", ":443", config)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Serving on %s\n", ":443")
	defer ln.Close()

	ln = s.NewListener(ln)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte("Hello World"))
	})
	if err = http.Serve(ln, mux); err != nil {
		fmt.Printf("web server err: %v\n", err)
	}
}
