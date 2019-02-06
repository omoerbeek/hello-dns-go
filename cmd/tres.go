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
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	mrand "math/rand"
	"net"
	"os"
	"strings"
	"time"

	"github.com/omoerbeek/hello-dns-go/tdns"
)

type (
	NameIPSet struct {
		Map map[string]map[string]net.IP
	}

	NameIP struct {
		Name string
		IP   net.IP
	}

	DNSResolver struct {
		DNSBufSize int
		logprefix string
	}

	ResolveResult struct {
		Res           []*tdns.RRec
		Intermediates []*tdns.RRec
	}

	NxdomainError struct{}
	NodataError   struct{}
)

var (
	hints = map[string]net.IP{
		"a.root-servers.net": net.ParseIP("198.41.0.4"),
		"f.root-servers.net": net.ParseIP("192.5.5.241"),
		"k.root-servers.net": net.ParseIP("193.0.14.129"),
	}
	roots NameIPSet = NewNameIPSet()
)

func (NxdomainError) Error() string {
	return "Nxdomain"
}

func (NodataError) Error() string {
	return "Nodata"
}

func NewNameIPSet() NameIPSet {
	return NameIPSet{make(map[string]map[string]net.IP)}
}

func (ips *NameIPSet) String() string {
	ret := strings.Builder{}
	count1 := 0
	for h, i := range ips.Map {
		ret.WriteString(h)
		ret.WriteString(": [")
		count2 := 0
		for _, j := range i {
			ret.WriteString(j.String())
			if count2 < len(i)-1 {
				ret.WriteString(", ")
			}
			count2++
		}
		ret.WriteString("]")
		if count1 < len(ips.Map)-1 {
			ret.WriteString(", ")
		}
		count1++
	}
	return ret.String()
}

func (ips *NameIPSet) Add(name *tdns.Name, ip net.IP) {
	key1 := name.K()
	key2 := ip.String()
	if ips.Map[key1] == nil {
		ips.Map[key1] = make(map[string]net.IP)
	}
	ips.Map[key1][key2] = ip
}

func (ips *NameIPSet) Size() (sum int) {
	for _, i := range ips.Map {
		sum += len(i)
	}
	return
}

// Flatten and randomize all the IPs we have
func (ips *NameIPSet) RandomizeIPs() (ret []NameIP) {
	for name, i := range ips.Map {
		for _, anip := range i {
			ret = append(ret, NameIP{name, anip})
		}
	}
	mrand.Shuffle(len(ret), func(i, j int) {
		ret[i], ret[j] = ret[j], ret[i]
	})
	return
}

func (res *DNSResolver) sendUDPQuery(nsip net.IP, writer *tdns.MessageWriter) (reader *tdns.MessageReader, err error) {
	address := net.UDPAddr{IP: nsip, Port: 53}
	conn, err := net.DialUDP("udp", nil, &address)
	if err != nil {
		return
	}
	defer conn.Close()

	msg := writer.Serialize()
	if _, err = conn.Write(msg); err != nil {
		fmt.Fprintf(os.Stderr, "Could not write query: %s\n", err)
		return
	}

	data := make([]byte, res.DNSBufSize)
	var n int
	// RFC 2308 talks about 120 seconds, I suppose that is not workable...
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err = conn.Read(data); err != nil {
		return
	}
	reader, err = tdns.NewMessagReader(data, n)
	return
}

func (res *DNSResolver) sendTCPQuery(nsip net.IP, writer *tdns.MessageWriter) (reader *tdns.MessageReader, err error) {
	address := net.TCPAddr{IP: nsip, Port: 53}
	dialer := net.Dialer{Timeout: 1 * time.Second}
	conn, err := dialer.Dial("tcp", address.String())
	//conn, err := net.DialTCP("tcp", nil, &address)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.(*net.TCPConn).SetNoDelay(true)

	msg := writer.Serialize()
	// RFC 2308 talks about 120 seconds, I suppose that is not workable...
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if err = binary.Write(conn, binary.BigEndian, uint16(len(msg))); err != nil {
		return
	}
	if _, err = conn.Write(msg); err != nil {
		return
	}
	//conn.CloseWrite()

	var l uint16
	if err = binary.Read(conn, binary.BigEndian, &l); err != nil {
		return
	}
	data := make([]byte, l)
	var n int
	// RFC 2308 talks about 120 seconds, I suppose that is not workable...
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err = conn.Read(data); err != nil {
		return
	}
	reader, err = tdns.NewMessagReader(data, n)
	return
}

func (res *DNSResolver) log(format string, args ...interface{}) {
	str := fmt.Sprintf(format, args...)
	fmt.Printf("%s%s\n", res.logprefix, str)
}


func (res *DNSResolver) getResponse(nsip net.IP, name *tdns.Name, dnstype tdns.Type, depth int) (reader *tdns.MessageReader, err error) {

	doTCP := false
	doEDNS := true

	for tries := 0; tries < 4; tries++ {
		// We declare a server including the fields mentioned in RFC 2308 7.2 plus TCP and EDNS
		server := tdns.BadServer{Address:nsip, TCP:doTCP, EDNS:doEDNS, Name:name, Type:dnstype}
		if server.IsBad() {
			res.log("%s %v %v is BAD, lets see if there's another", nsip, doTCP, doEDNS)
			if !doTCP {
				if doEDNS {
					doEDNS = false;
					continue
				} else {
					doTCP = true
					continue
				}
			} else {
				if doEDNS {
					doEDNS = false
					continue
				} else {
					return nil, fmt.Errorf("no non-BAD servers left")
				}
			}
		}

		writer := tdns.NewMessageWriter(name, dnstype, tdns.IN, math.MaxUint16)

		if doEDNS {
			writer.SetEDNS(res.DNSBufSize, false, tdns.Noerror)
		}

		// Use a good random source out of principle
		r, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint16+1))
		writer.DH.Id = uint16(r.Int64())


		if doTCP {
			if reader, err = res.sendTCPQuery(nsip, writer); err != nil {
				res.log("%d %s INCREASING BADNESSS", tries, server.String())
				server.Bad()
				return
			}
		} else {
			if reader, err = res.sendUDPQuery(nsip, writer); err != nil {
				res.log("%d %s INCREASING BADNESSS", tries, server.String())
				doTCP = true
				server.Bad()
				continue
			}
		}
		// for security reasons, you really need this
		if reader.DH.Id != writer.DH.Id {
			res.log("ID mismatch on answer")
			continue
		}
		if reader.DH.Bit(tdns.QrMask) == 0 {
			res.log("What we received was not a response, ignoring")
			continue
		}
		if reader.DH.Rcode() == tdns.Formerr {
			// XXX this should check that there is no OPT in the response
			res.log("Got a Formerr, resending without EDNS")
			doEDNS = false
			continue
		}
		if reader.DH.Bit(tdns.TcMask) == 1 {
			res.log("Got a truncated answer, retrying over TCP")
			doTCP = true
			continue
		}
		// It was an answer to our satisfaction
		return
	}
	return nil, fmt.Errorf("Giving up on %s", nsip.String())
}

func (resolver *DNSResolver) resolveAt(name *tdns.Name, dnstype tdns.Type, depth int, auth *tdns.Name, mservers *NameIPSet) (ret ResolveResult, err error) {
	oldprefix := resolver.logprefix
	resolver.logprefix = fmt.Sprintf("%s%s|%s ", strings.Repeat(" ", depth), name, dnstype)
	defer func () { resolver.logprefix = oldprefix }()

	resolver.log("Starting query at authority = %s, have %d addresses to try", auth, mservers.Size())

	servers := mservers.RandomizeIPs()

	for serverindex, server := range servers {
		var newAuth tdns.Name

		resolver.log("Sending to server %s at %s", server.Name, server.IP)

		var reader *tdns.MessageReader

		reader, err = resolver.getResponse(server.IP, name, dnstype, depth)
		if err != nil {
			resolver.log("%s", err)
			continue
		}

		if !reader.Name.Equals(name) || reader.Type != dnstype {
			resolver.log("Got a response %s to a different question %s or different %s %s type than we asked for!",
				reader.Name.String(), name.String(), reader.Type, dnstype)
			continue // see if another server wants to work with us
		}

		// In a real resolver, you must ignore NXDOMAIN in case of a CNAME.
		// Because that is how the intern et rolls.
		if reader.DH.Rcode() == tdns.Nxdomain {
			resolver.log("Got an Nxdomain, it does not exist")
			err = NxdomainError{}
			return
		} else if reader.DH.Rcode() != tdns.Noerror {
			resolver.log("Answer from authoritative server had an error %s", reader.DH.Rcode())
			if reader.DH.Rcode() == tdns.Servfail && serverindex < len(servers)-1 {
				continue
			}
			err = fmt.Errorf("Answer from authoritative server had an error: %s", reader.DH.Rcode())
			return
		}
		if reader.DH.Bit(tdns.AaMask) == 1 {
			resolver.log("Answer says it is authorative")
		}

		var nsses = make(map[string]*tdns.Name)
		var addresses = NewNameIPSet()

		for rrec := reader.GetRR(); rrec != nil; rrec = reader.GetRR() {
			resolver.log("%s", rrec)

			if reader.DH.Bit(tdns.AaMask) == 1 {
				// Authoritative answer. We trust this.
				if rrec.Section == tdns.Answer && name.Equals(&rrec.Name) && dnstype == rrec.Type {
					resolver.log("We got an answer to our question!")
					ret.Res = append(ret.Res, rrec)
				} else if name.Equals(&rrec.Name) && rrec.Type == tdns.CNAME {
					// CNAME handling
					target := rrec.Data.(*tdns.CNAMEGen).CName
					ret.Intermediates = append(ret.Intermediates, rrec)
					resolver.log("We got a CNAME to %s, chasing", name.String())
					if target.IsPartOf(auth) {
						resolver.log("Target %s is within %s, harvesting from packet", target, auth)
						hadMatch := false
						for rrec = reader.GetRR(); rrec != nil; rrec = reader.GetRR() {
							if rrec.Section == tdns.Answer && rrec.Name.Equals(target) && rrec.Type == dnstype {
								hadMatch = true
								ret.Res = append(ret.Res, rrec)
							}
						}
						if hadMatch {
							resolver.log("In-message chase worked, we're done")
							return
						} else {
							resolver.log("In-message chase not succesful, will do new query for %s", target)
						}
					}

					var chaseres ResolveResult
					chaseres, err = resolver.resolveAt(target, dnstype, depth+1, tdns.MakeName(""), &roots)
					if err == nil {
						ret.Res = chaseres.Res
						for _, i := range chaseres.Intermediates {
							ret.Intermediates = append(ret.Intermediates, i)
						}
					}
					return
				}
			} else {
				// Not authorative answer, pick up nameservers. We check if glue records are within the authority
				// of what we approached this server for.
				if rrec.Section == tdns.Authority && rrec.Type == tdns.NS {
					if name.IsPartOf(&rrec.Name) {
						nsname := rrec.Data.(*tdns.NSGen).NSName
						nsses[nsname.K()] = nsname
						newAuth = rrec.Name
					} else {
						resolver.log("Authoritative server gave us NS record to which this query does not belong")
					}
				} else if rrec.Section == tdns.Additional && nsses[rrec.Name.K()] != nil && (rrec.Type == tdns.A || rrec.Type == tdns.AAAA) {
					if rrec.Name.IsPartOf(auth) {
						switch a := rrec.Data.(type) {
						case *tdns.AGen:
							addresses.Add(&rrec.Name, a.IP)
						case *tdns.AAAAGen:
							addresses.Add(&rrec.Name, a.IP)
						}
					} else {
						resolver.log("Not accepting IP address of %s: out of authority of this server", rrec.Name.String())
					}
				}
			}

		}
		if len(ret.Res) > 0 {
			resolver.log("Done, returning %d results, %d intermediate", len(ret.Res), len(ret.Intermediates))
			return
		} else if reader.DH.Bit(tdns.AaMask) == 1 {
			resolver.log("No data response")
			err = NodataError{}
			return
		}

		resolver.log("We got delegated to %d %s nameserver names", len(nsses), newAuth.String())
		numa := addresses.Size()
		if numa > 0 {
			resolver.log("We have %d addresses to iterate to: %s", numa, addresses.String())
			res2, err2 := resolver.resolveAt(name, dnstype, depth+1, &newAuth, &addresses)
			if err2 != nil {
				return res2, err2
			}
			if len(res2.Res) > 0 {
				return res2, err2
			}
			resolver.log("The IP addresses we had dit not provide a good answer")

		}
		// well we could not make it work using the servers we had addresses for. Let's try
		// to get addresses for the rest
		resolver.log("Don't have a resolved nameserver to ask anymore, trying to resolve %d names", len(nsses))
		var rnsses []tdns.Name
		for _, n := range nsses {
			rnsses = append(rnsses, *n)
		}
		mrand.Shuffle(len(rnsses), func(i, j int) {
			rnsses[i], rnsses[j] = rnsses[j], rnsses[i]
		})

		for _, n := range rnsses {
			for _, t := range []tdns.Type{tdns.A, tdns.AAAA} {
				newns := NewNameIPSet()
				resolver.log("Attempting to resolve NS %s|%s", n.String(), t)
				result, err := resolver.resolveAt(&n, t, depth+1, tdns.MakeName(""), &roots)
				if err != nil {
					resolver.log("Failed to resolve ns name for %s %s: %s, trying next server (if there)", n.String(), t, err)
					continue
				}
				resolver.log("Got %d nameserver %s addresses, adding to list", len(result.Res), t)
				for _, res := range result.Res {
					switch a := res.Data.(type) {
					case *tdns.AGen:
						newns.Add(&n, a.IP)
					case *tdns.AAAAGen:
						newns.Add(&n, a.IP)
					}
				}
				if newns.Size() == 0 {
					resolver.log("Failed to resolve name for %s %s", n.String(), t)
					continue
				}
				res2, err := resolver.resolveAt(name, dnstype, depth+1, &newAuth, &newns)
				if err != nil {
					_, isNd := err.(NodataError)
					_, isNx := err.(NxdomainError)
					if !isNd && !isNx {
						resolver.log("Failed to resolve name for %s %s: %s trying next server (if there)", n.String(), t, err)
						continue
					} else {
						return res2, err
					}
				}
				if len(res2.Res) > 0 {
					return res2, nil
				}
				// Try AAAA
			}
			// Try next NS
		}
		return
	}
	return
}

func resolveHints() {
	// We do not explicitly randomize this map, since golang already
	// does this.
	empty := DNSResolver{DNSBufSize: 4000}
	for _, ip := range hints {
		fmt.Println("Using hint", ip)
		reader, err := empty.getResponse(ip, tdns.MakeName("."), tdns.NS, 0)
		if err != nil {
			continue
		}
		var rrec *tdns.RRec
		for rrec = reader.GetRR(); rrec != nil; rrec = reader.GetRR() {
			switch a := rrec.Data.(type) {
			case *tdns.AGen:
				roots.Add(&rrec.Name, a.IP)
			case *tdns.AAAAGen:
				roots.Add(&rrec.Name, a.IP)
			}
		}
		if len(roots.Map) > 0 {
			// We found at least one
			break
		}
	}
}

func (r *DNSResolver) processQuery(conn *net.UDPConn, address *net.UDPAddr, reader *tdns.MessageReader) {
	writer := tdns.NewMessageWriter(&reader.Name, reader.Type, tdns.IN, math.MaxUint16)

	writer.DH.SetBitValue(tdns.RdMask, reader.DH.Bit(tdns.RdMask))
	writer.DH.SetBit(tdns.RaMask)
	writer.DH.SetBit(tdns.QrMask)
	writer.DH.Id = reader.DH.Id

	resolver := DNSResolver{DNSBufSize: 4000}

	res, err := resolver.resolveAt(&reader.Name, reader.Type, 0, tdns.MakeName(""), &roots)

	resolver.log("Result of query for %s|%s %d/%d", reader.Name.String(), reader.Type, len(res.Intermediates), len(res.Res))
	for _, r := range res.Intermediates {
		resolver.log("%s", r.String())
	}
	for _, r := range res.Res {
		resolver.log("%s", r.String())
	}
	resolver.log("BAD server map %s\n", tdns.BadServersInfo())

	// XXX numqueries

	switch err.(type) {
	case nil:
		for _, r := range res.Intermediates {
			writer.PutRR(tdns.Answer, &r.Name, r.Type, r.TTL, r.Class, r.Data)
		}
		for _, r := range res.Res {
			writer.PutRR(tdns.Answer, &r.Name, r.Type, r.TTL, r.Class, r.Data)
		}
	case NodataError:
		resolver.log("Nodata for %s|%s", reader.Name.String(), reader.Type)
	case NxdomainError:
		resolver.log("Nxdomain for %s|%s", reader.Name.String(), reader.Type)
		writer.DH.SetRcode(tdns.Nxdomain)
	}
	conn.WriteTo(writer.Serialize(), address)
}

func doListen(listenAddress string) {
	address, err := net.ResolveUDPAddr("udp", listenAddress)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	conn, err := net.ListenUDP("udp", address)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	buf := make([]byte, 4096)
	for {
		n, address, err := conn.ReadFrom(buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}
		fmt.Printf("Received packet from %s\n", address)
		reader, err := tdns.NewMessagReader(buf, n)
		if err != nil {
			continue
		}
		if reader.DH.Bit(tdns.QrMask) == 1 {
			fmt.Printf("Received packet from %s was not a query\n", address)
			continue
		}
		r := DNSResolver{DNSBufSize:1500}
		go r.processQuery(conn, address.(*net.UDPAddr), reader)
	}
}

func main() {
	args := os.Args
	if len(args) != 2 && len(args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: tres name type\n")
		fmt.Fprintf(os.Stderr, "       tres ip:port\n")
		os.Exit(1)
	}

	go tdns.RunBadServers()

	resolveHints()
	fmt.Printf("Retrieved . NSSET from hints, have %d addresses\n", roots.Size())

	if len(args) == 2 {
		doListen(args[1])
	}
	dn := tdns.MakeName(args[1])
	dt := tdns.MakeType(args[2])

	resolver := DNSResolver{DNSBufSize: 4000}
	res, err := resolver.resolveAt(dn, dt, 0, tdns.MakeName(""), &roots)

	if err != nil {
		fmt.Printf("Error result for %s %s: %s\n", args[1], args[2], err)
		os.Exit(1)
	}
	if len(res.Res) == 0 {
		fmt.Printf("No data for %s %s\n", args[1], args[2])
	} else {
		for _, r := range res.Intermediates {
			fmt.Printf("Intermediate %s\n", r.String())
		}
		for _, r := range res.Res {
			fmt.Printf("Resolved %s\n", r.String())
		}
	}
	os.Exit(0)
}
