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
	"math"
	"math/big"
	"crypto/rand"

	"github.com/omoerbeek/hello-dns-go/tdns"
)

var (
	hints = map[string]net.IP{
		"a.root-servers.net": net.ParseIP("198.41.0.4"),
		"f.root-servers.net": net.ParseIP("192.5.5.241"),
		"k.root-servers.net": net.ParseIP("193.0.14.129"),
	}
	roots map[string]map[string]net.IP = make(map[string]map[string]net.IP)
)

func sendUDPQuery(nsip *net.IP, name *tdns.Name, dnstype tdns.Type) (reader *tdns.MessageReader, wrId uint16, err error) {
	conn, err := net.Dial("udp", nsip.String() + ":53")
	if err != nil {
		return
	}
        writer := tdns.NewDNSMessageWriter(name, dnstype, tdns.IN, math.MaxUint16)
        writer.DH.SetBit(tdns.RdMask)
        writer.SetEDNS(4000, false, tdns.Noerror);

        // Use a good random source out of principle
        r, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint16+1))
	wrId = uint16(r.Int64())
        writer.DH.Id = wrId

        msg := writer.Serialize()
        if _, err := conn.Write(msg); err != nil {
                fmt.Fprintf(os.Stderr, "Could not write query: %s\n", err)
                os.Exit(1)
        }

        data := make([]byte, math.MaxUint16)
        var n int
        if n, err = conn.Read(data); err != nil {
		return
	}
	reader, err = tdns.NewMessagReader(data, n)
	return
}

func resolveName(name *tdns.Name, nsip *net.IP, typ tdns.Type) (ret []tdns.RRec, errr error) {
	prefix := ""
	reader, wrId, err := sendUDPQuery(nsip, name, typ)
	if err != nil {
		return nil, err
	}
	for tries := -0; tries < 4; tries++ {
		// for security reasons, you really need this
		if reader.DH.Id != wrId {
			fmt.Printf("%sID mismatch on answer\n");
			continue
		}
		if (!reader.DH.Bit(tdns.QrMask)) {
			fmt.Printf("%sWhat we received was not a response, ignoring\n");
			continue
		}
		if reader.DH.Rcode() == tdns.Formerr {
			// XXX this should check that there is no OPT in the response
			fmt.Printf("%sGot a Formerr, resending without EDNS\n", prefix)
			// XXX
			continue
		}
		if (reader.DH.Bit(tdns.TcMask)) {
			fmt.Printf("%sGot a truncated answer, retrying over TCP\n");
			// XXX
			continue
		}
		ret = make([]tdns.RRec, 0)
		var rrec *tdns.RRec
		for rrec = reader.GetRR(); rrec != nil; rrec = reader.GetRR() {	
			ret = append(ret, *rrec)
		}
		return ret, nil
	}
	return nil, nil
}

func resolveHints() {
	// We do not explicitly randomize maps, since golang already
	// does this.
	for _, ip := range hints {
		fmt.Println("Using hint", ip)
		rrecs, err := resolveName(tdns.MakeName("."), &ip, tdns.NS)
		if err != nil {
			continue;
		}
		for _, rrec := range rrecs {
			key := rrec.Name.String()
			switch a := rrec.Data.(type) {
			case *tdns.AGen: 
				if roots[key] == nil {
					roots[key] = make(map[string]net.IP)
				}
				key2 := a.IP.String();
				roots[key][key2] = a.IP
			case *tdns.AAAAGen: 
				if roots[key] == nil {
					roots[key] = make(map[string]net.IP)
				}
				key2 := a.IP.String();
				roots[key][key2] = a.IP
			}
		}
		if len(roots) > 0 {
			// We found at least one
			break
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
