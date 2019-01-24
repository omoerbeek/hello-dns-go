/*
 * Copyright (c) 2019 Otto Moerbeek otto@drijf.net
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package main

import (
	"fmt"
	"net"
	"os"

	"github.com/omoerbeek/hello-dns-go/tdns"
)

var (
	hints = map[*tdns.Name]net.IP{
		tdns.MakeName("a.root-servers.net"): net.ParseIP("198.41.0.4"),
		tdns.MakeName("f.root-servers.net"): net.ParseIP("192.5.5.241"),
		tdns.MakeName("k.root-servers.net"): net.ParseIP("193.0.14.129"),
	}
	roots map[*tdns.Name][]net.IP = make(map[*tdns.Name][]net.IP)
)

type RRec struct {
	Type tdns.Type
	Data tdns.RRGen
}

func resolveName(name *tdns.Name, ip *net.IP, typ tdns.Type) []RRec {
	x := make([]RRec, 2)
	a := tdns.AGen{net.ParseIP("1.2.3.4")}
	aaaa := tdns.AGen{net.ParseIP("::1")}
	x[0] = RRec{tdns.A, &a}
	x[1] = RRec{tdns.A, &aaaa}
	return x
}

func resolveHints() {
	for name, ip := range hints {
		rrecs := resolveName(name, &ip, tdns.NS)
		for _, rrec := range rrecs {
			switch rrec.Type {
			case tdns.A:
				a := rrec.Data.(*tdns.AGen)
				roots[name] = append(roots[name], a.IP)
				break
			case tdns.AAAA:
				a := rrec.Data.(*tdns.AAAAGen)
				roots[name] = append(roots[name], a.IP)
				break
			}
		}
	}
}

func main() {
	args := os.Args
	if len(args) != 2 && len(args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: tres name type\n")
		fmt.Fprintf(os.Stderr, "       tres ip:port\n")
		os.Exit(1)
	}
	resolveHints()
	fmt.Println("Hints resolve to", roots)
	os.Exit(0)
}