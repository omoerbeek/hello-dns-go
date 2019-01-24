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
	hints = map[string]net.IP{
		"a.root-servers.net": net.ParseIP("198.41.0.4"),
		"f.root-servers.net": net.ParseIP("192.5.5.241"),
		"k.root-servers.net": net.ParseIP("193.0.14.129"),
	}
	roots map[string][]net.IP = make(map[string][]net.IP)
)

type RRec struct {
	Name tdns.Name
	Data tdns.RRGen
}

func resolveName(name *tdns.Name, nsip *net.IP, typ tdns.Type) []RRec {
	x := make([]RRec, 2)
	a := tdns.AGen{net.ParseIP("1.2.3.4")}
	aaaa := tdns.AAAAGen{net.ParseIP("::1")}
	x[0] = RRec{*name, &a}
	x[1] = RRec{*name, &aaaa}
	return x
}

func resolveHints() {
	for name, ip := range hints {
		rrecs := resolveName(tdns.MakeName(name), &ip, tdns.NS)
		for _, rrec := range rrecs {
			key := rrec.Name.String()
			switch a := rrec.Data.(type) {
			case *tdns.AGen: 
				roots[key] = append(roots[key], a.IP)
			case *tdns.AAAAGen: 
				roots[key] = append(roots[key], a.IP)
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
