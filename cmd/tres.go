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

	DNSResolver struct {
		DNSBufSize int
		DoIPv6     bool
		logprefix  string
		numQueries int
	}

	NxdomainError struct{}
	NodataError   struct{}
	Servfail      struct{}
)

var (
	hints = map[string]net.IP{
		"a.root-servers.net": net.ParseIP("198.41.0.4"),
		"f.root-servers.net": net.ParseIP("192.5.5.241"),
		"k.root-servers.net": net.ParseIP("193.0.14.129"),
	}
	roots = NewNameIPSet()

	badServers     = tdns.NewBadServerCache()
	negResultCache = tdns.NewResultCache()
	rrCache        = tdns.NewRRCache()
)

func (NxdomainError) Error() string {
	return "Nxdomain"
}

func (NodataError) Error() string {
	return "Nodata"
}

func (Servfail) Error() string {
	return "Servfail"
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
func (ips *NameIPSet) RandomizeIPs() (ret []tdns.NameIP) {
	for name, i := range ips.Map {
		for _, anip := range i {
			ret = append(ret, tdns.NameIP{Name: name, IP: anip})
		}
	}
	mrand.Shuffle(len(ret), func(i, j int) {
		ret[i], ret[j] = ret[j], ret[i]
	})
	return
}

func (resolver *DNSResolver) sendUDPQuery(nsip net.IP, writer *tdns.MessageWriter) (reader tdns.MessageReaderInterface, err error) {
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

	data := make([]byte, resolver.DNSBufSize)
	var n int
	// RFC 2308 talks about 120 seconds, I suppose that is not workable...
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err = conn.Read(data); err != nil {
		return
	}
	reader, err = tdns.NewMessagReader(data, n)
	return
}

func (resolver *DNSResolver) sendTCPQuery(nsip net.IP, writer *tdns.MessageWriter) (reader tdns.MessageReaderInterface, err error) {
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
	read := 0
	for count := 0; count < 3 && read < int(l); count++ {
		// RFC 2308 talks about 120 seconds, I suppose that is not workable...
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var n int
		if n, err = conn.Read(data[read:]); err != nil {
			return
		}
		read += n
	}
	if read < int(l) {
		return nil, fmt.Errorf("read timeout")
	}
	reader, err = tdns.NewMessagReader(data, read)
	return
}

func (resolver *DNSResolver) log(format string, args ...interface{}) {
	str := fmt.Sprintf(format, args...)
	fmt.Printf("%s%s\n", resolver.logprefix, str)
}

func (resolver *DNSResolver) getResponse(ns tdns.NameIP, name *tdns.Name, dnstype tdns.Type) (reader tdns.MessageReaderInterface, err error) {

	resolver.log("Asking cache: %s %s", name, dnstype)
	reader = rrCache.GetRRSet(name, dnstype)
	if reader != nil {
		if reader.Answers() {
			resolver.log("Result from cache!")
			return reader, nil
		}
	}

	resolver.log("Sending to server %s at %s", ns.Name, ns.IP)

	doTCP := false
	doEDNS := true

	for tries := 0; tries < 4; tries++ {
		// We could identify a server using the fields mentioned in RFC 2308 7.2 plus TCP and EDNS
		// But lets diffrentiate between UDP/TCP and EDNS only
		server := tdns.BadServer{Address: ns.IP, TCP: doTCP, EDNS: doEDNS, Name: nil, Type: 0}
		if badServers.IsBad(&server) {
			resolver.log("%s tcp=%v edns=%v is BAD, lets see if there's another", ns.IP, doTCP, doEDNS)
			if !doTCP {
				if doEDNS {
					doEDNS = false
					resolver.log("%s continuing with tcp=%v edns=%v", ns.IP, doTCP, doEDNS)
					continue
				} else {
					doTCP = true
					doEDNS = true
					resolver.log("%s continuing with tcp=%v edns=%v", ns.IP, doTCP, doEDNS)
					continue
				}
			} else {
				if doEDNS {
					doEDNS = false
					resolver.log("%s continuing with tcp=%v edns=%v", ns.IP, doTCP, doEDNS)
					continue
				} else {
					return nil, fmt.Errorf("no non-BAD servers left")
				}
			}
		}

		writer := tdns.NewMessageWriter(name, dnstype, tdns.IN, math.MaxUint16)

		if doEDNS {
			writer.SetEDNS(resolver.DNSBufSize, true, tdns.Noerror)
		}

		// Use a good random source out of principle
		r, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint16+1))
		writer.DH.Id = uint16(r.Int64())

		resolver.numQueries++
		if doTCP {
			if reader, err = resolver.sendTCPQuery(ns.IP, writer); err != nil {
				resolver.log("%d %s increasing badnesss", tries, server.String())
				badServers.Bad(&server)
				return
			}
		} else {
			if reader, err = resolver.sendUDPQuery(ns.IP, writer); err != nil {
				resolver.log("%d %s increasing badnesss", tries, server.String())
				doTCP = true
				badServers.Bad(&server)
				continue
			}
		}
		// for security reasons, you really need this
		if reader.DH().Id != writer.DH.Id {
			resolver.log("ID mismatch on answer")
			continue
		}
		if reader.DH().Bit(tdns.QrMask) == 0 {
			resolver.log("What we received was not a response, ignoring")
			continue
		}
		if reader.DH().Rcode() == tdns.Formerr {
			// XXX this should check that there is no OPT in the response
			resolver.log("Got a Formerr, resending without EDNS")
			doEDNS = false
			continue
		}
		if reader.DH().Bit(tdns.TcMask) == 1 {
			resolver.log("Got a truncated answer, retrying over TCP")
			doTCP = true
			continue
		}
		// It was an answer to our satisfaction
		return
	}
	return nil, fmt.Errorf("giving up on %s", ns.IP.String())
}

func (resolver *DNSResolver) resolveAt(name *tdns.Name, dnstype tdns.Type, depth int, auth *tdns.Name, mservers *NameIPSet) (ret tdns.ResolveResult, err error) {
	oldprefix := resolver.logprefix
	resolver.logprefix = fmt.Sprintf("%s%s|%s ", strings.Repeat(" ", depth), name, dnstype)
	defer func() { resolver.logprefix = oldprefix }()

	negcached, err := negResultCache.Get(name, dnstype)
	if negcached != nil {
		resolver.log("Found in negResultCache")
		return *negcached, err
	}

	result, err := resolver.resolveAt1(name, dnstype, depth, auth, mservers)
	if err == nil {
		//resultCache.Put(name, dnstype, &result, nil)
	} else {
		resolver.log("PUT IN NEGCACHE %s %s", name, dnstype)
		negResultCache.Put(name, dnstype, &result, err)
	}
	return result, err
}

func (resolver *DNSResolver) resolveAt1(name *tdns.Name, dnstype tdns.Type, depth int, auth *tdns.Name, mservers *NameIPSet) (ret tdns.ResolveResult, err error) {

	if resolver.numQueries > 100 {
		err = Servfail{}
		return
	}
	oldprefix := resolver.logprefix
	resolver.logprefix = fmt.Sprintf("%s%s|%s ", strings.Repeat(" ", depth), name, dnstype)
	defer func() { resolver.logprefix = oldprefix }()
	resolver.log("Starting query at authority = %s, have %d addresses to try", auth, mservers.Size())

	var nsservers []tdns.NameIP
	if dnstype == tdns.DS {
		nsservers = rrCache.GetNS(name.Parent())
	} else {
		nsservers = rrCache.GetNS(name)
	}

	var servers []tdns.NameIP
	if nsservers != nil {
		servers = nsservers
	} else {
		servers = mservers.RandomizeIPs()
	}

	for serverindex, server := range servers {

		if !resolver.DoIPv6 && server.IP.To4() == nil {
			continue
		}

		var newAuth tdns.Name
		var reader tdns.MessageReaderInterface

		reader, err = resolver.getResponse(server, name, dnstype)
		if err != nil {
			resolver.log("%s", err)
			continue
		}

		if !reader.Name().Equals(name) || reader.Type() != dnstype {
			resolver.log("Got a response %s to a different question %s or different %s %s type than we asked for!",
				reader.Name().String(), name.String(), reader.Type(), dnstype)
			continue // see if another server wants to work with us
		}

		// In a real resolver, you must ignore NXDOMAIN in case of a CNAME.
		// Because that is how the intern et rolls.
		if reader.DH().Rcode() == tdns.Nxdomain {
			resolver.log("Got an Nxdomain, it does not exist")
			for rrec := reader.GetRR(); rrec != nil; rrec = reader.GetRR() {
				resolver.log("Auths RR: %s", rrec)
				if rrec.Section == tdns.Authority {
					ret.Auths = append(ret.Auths, rrec)
				}
			}
			err = NxdomainError{}
			return
		} else if reader.DH().Rcode() != tdns.Noerror {
			resolver.log("Answer from authoritative server had an error %s", reader.DH().Rcode())
			if reader.DH().Rcode() == tdns.Servfail && serverindex < len(servers)-1 {
				continue
			}
			err = fmt.Errorf("answer from authoritative server had an error: %s", reader.DH().Rcode())
			return
		}

		if reader.FromCache() {
			resolver.log("Answer says it is from the cache")
		}
		resolver.log("Header %s", reader.DH())

		if reader.DH().Bit(tdns.AaMask) == 1 {
			resolver.log("Answer says it is authorative")
		}

		var nsses = make(map[string]*tdns.Name)
		var addresses = NewNameIPSet()

		// XXX Cache poisoning!
		rrCache.Put(reader)

		for rrec := reader.FirstRR(); rrec != nil; rrec = reader.GetRR() {

			resolver.log("RR(%s): %s", rrec.Section, rrec)

			// Pick up nameservers. We check if glue records are within the authority
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
			if rrec.Section == tdns.Authority && rrec.Type == tdns.SOA {
				ret.Auths = append(ret.Auths, rrec)
			}

			if reader.DH().Bit(tdns.AaMask) == 1 {
				// Authoritative answer. We trust this.
				if rrec.Section == tdns.Answer && name.Equals(&rrec.Name) && dnstype == rrec.Type {
					resolver.log("We got an answer to our question!")
					ret.Answers = append(ret.Answers, rrec)
				} else if name.Equals(&rrec.Name) && rrec.Type == tdns.CNAME {
					// CNAME handling
					target := rrec.Data.(*tdns.CNAMEGen).CName
					ret.Intermediates = append(ret.Intermediates, rrec)
					resolver.log("We got a CNAME to %s, chasing", name.String())
					if !reader.FromCache() && target.IsPartOf(auth) {
						resolver.log("Target %s is within %s, harvesting from packet", target, auth)
						hadMatch := false
						for hrrec := reader.GetRR(); hrrec != nil; hrrec = reader.GetRR() {
							if hrrec.Section == tdns.Answer && hrrec.Name.Equals(target) && hrrec.Type == dnstype {
								hadMatch = true
								rrec = hrrec
								ret.Answers = append(ret.Answers, rrec)
							}
						}
						if hadMatch {
							resolver.log("In-message chase worked, we're done")
							return
						} else {
							resolver.log("In-message chase not succesful, will do new query for %s", target)
						}
					}

					var chaseres tdns.ResolveResult
					chaseres, err = resolver.resolveAt1(target, dnstype, depth+1, tdns.MakeName(""), &roots)
					if err == nil {
						ret.Answers = chaseres.Answers
						for _, i := range chaseres.Intermediates {
							ret.Intermediates = append(ret.Intermediates, i)
						}
					}
					return
				}
			}
		}

		numa := addresses.Size()
		numns := len(nsses)

		if len(ret.Answers) > 0 {
			resolver.log("DEL IN NEGCACHE %s %s", name, dnstype)
			negResultCache.Del(name, dnstype)
			resolver.log("Done, returning %d results, %d intermediate", len(ret.Answers), len(ret.Intermediates))
			return
		} else if reader.DH().Bit(tdns.AaMask) == 1 && numa == 0 && numns == 0 {
			resolver.log("No data response")
			err = NodataError{}
			return
		}

		resolver.log("We got delegated to %d %s nameserver names", numns, newAuth.String())
		if numa > 0 {
			resolver.log("We have %d addresses to iterate to", numa)
			res2, err2 := resolver.resolveAt1(name, dnstype, depth+1, &newAuth, &addresses)
			//if err2 != nil {
			//	return res2, err2
			//}
			if len(res2.Answers) > 0 {
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
				var result tdns.ResolveResult
				result, err = resolver.resolveAt1(&n, t, depth+1, tdns.MakeName(""), &roots)
				if err != nil {
					resolver.log("Failed to resolve ns name for %s %s: %s, trying next server (if there)", n.String(), t, err)
					continue
				}
				resolver.log("Got %d nameserver %s addresses, adding to list", len(result.Answers), t)
				for _, res := range result.Answers {
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
				var res2 tdns.ResolveResult
				res2, err = resolver.resolveAt1(name, dnstype, depth+1, &newAuth, &newns)
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
				if len(res2.Answers) > 0 {
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

/*
func x() {
	if dnstype == tdns.DNSKEY {
		var dsrecords []*tdns.RRec
		if name.Empty() {
			dsrecords = tdns.TrustAnchor
		} else {
			//parent := name.Parent()
			var ds tdns.ResolveResult
			ds, err = resolver.resolveAt(name, tdns.DS, depth+1, tdns.MakeName("."), &roots)
			if err == nil {
				dsrecords = ds.Answers
			} else {
				return
			}
		}
		resolver.log("Going to validate DNSKEY for %s with %v", name, dsrecords)
		var validated bool
		err = tdns.Validate(reader, dsrecords, &validated)
		resolver.log("Validate %s returned %v", name, err)
		if err != nil {
			return
		}
	}
}
*/

func (resolver *DNSResolver) ValidateRRSet(dnstype tdns.Type, zonekeys []*tdns.RRec, rrset, rrsigs []*tdns.RRec) error {

	resolver.log("Checking %d %s %d RRSIGs", len(rrset), dnstype.String(), len(rrsigs))

	for _, rec := range rrsigs {
		resolver.log("Checking %s", rec)
		found := rec.Data.(*tdns.RRSIGGen)
		if found.Type != dnstype {
			resolver.log("type mismtatch")
			//resolver.ValidateRRSIG(dnstype, rrsig)
			continue
		}
		for _, dnskey := range zonekeys {
			keydata := dnskey.Data.(*tdns.DNSKEYGen)
			if keydata.Flags&tdns.ZONE == 0 {
				resolver.log("no zone key")
				continue
			}
			if keydata.Flags&tdns.REVOKE != 0 {
				resolver.log("revoked key")
				continue
			}
			if keydata.Algorithm != found.Algorithm {
				resolver.log("algorithm mismatch")
				continue
			}
			if keydata.KeyTag() != found.KeyTag {
				resolver.log("keytag mismatch %d %d", keydata.KeyTag(), found.KeyTag)
				continue
			}
			if !dnskey.Name.Equals(found.Signer) {
				resolver.log("signer mismatch")
				continue
			}
			resolver.log("FOUND MATCHING DNSKEY %s FOR RRSIG %s", dnskey, found)
			err := tdns.ValidateRSA(rrset, keydata, rec)
			if err != nil {
				return err
			}
			return nil
		}

	}
	return fmt.Errorf("no matching DNSKEY found")
}

func (resolver *DNSResolver) ValidateRoot(zonekeys []*tdns.RRec, reader tdns.MessageReaderInterface) error {
	// First take a look at the answers only

	split := make(map[tdns.Type][]*tdns.RRec)
	for rrec := reader.FirstRR(); rrec != nil; rrec = reader.GetRR() {
		if rrec.Section == tdns.Answer {
			split[rrec.Type] = append(split[rrec.Type], rrec)
		}
	}
	rrsigs := split[tdns.RRSIG]
	for dnstype, recs := range split {
		if dnstype == tdns.RRSIG {
			continue
		}
		if err := resolver.ValidateRRSet(dnstype, zonekeys, recs, rrsigs); err != nil {
			return err
		} else {
			return nil
		}

	}
	return fmt.Errorf("no validation took place")
}

func resolveRootHints() {
	// We do not explicitly randomize this map, since golang already
	// does this.
	res := DNSResolver{DNSBufSize: 4000}
	root := tdns.MakeName(".")
	var rootkey *tdns.RRec
	var allrootkeys []*tdns.RRec
	var reader tdns.MessageReaderInterface
	var err error

outer:
	for name, ip := range hints {
		fmt.Println("Using hint for DNSKEY", ip)
		nameip := tdns.NameIP{Name: name, IP: ip}

		reader, err = res.getResponse(nameip, root, tdns.DNSKEY)
		if err != nil {
			continue
		}
		for rrec := reader.GetRR(); rrec != nil; rrec = reader.GetRR() {
			switch a := rrec.Data.(type) {
			case *tdns.DNSKEYGen:
				err := tdns.ValidateDNSKeyWithDS(root, a, tdns.TrustAnchor)
				if err == nil {
					rootkey = rrec
					res.log("Valid root DNSKEY found keytag is %d", a.KeyTag())
					res.log("%s", rootkey)
					break outer
				} else {
					res.log("Invalid rootkey: %s, trying next", err)
				}
			}
		}
	}
	if rootkey == nil {
		panic("No valid rootkey found")
	}

	for rrec := reader.FirstRR(); rrec != nil; rrec = reader.GetRR() {
		switch rrec.Data.(type) {
		case *tdns.DNSKEYGen:
			allrootkeys = append(allrootkeys, rrec)
		}
	}
	res.log("\nFound %d DNSKEY records", len(allrootkeys))

	zonekeys := []*tdns.RRec{rootkey}

	if err := res.ValidateRoot(zonekeys, reader); err != nil {
		panic(fmt.Sprint("validation of root DNSKEYS failed: ", err))
	} else {
		res.log("root DNSKEY validation OK")
	}

	for name, ip := range hints {
		fmt.Println("Using hint for . NS servers", ip)
		nameip := tdns.NameIP{Name: name, IP: ip}
		reader, err := res.getResponse(nameip, root, tdns.NS)
		if err != nil {
			continue
		}
		res.log("Validating hints")
		if err = res.ValidateRoot(allrootkeys, reader); err != nil {
			res.log("Validation failed: %s", err)
			continue
		} else {
			res.log("Good validation of root NS records")
		}
		for rrec := reader.FirstRR(); rrec != nil; rrec = reader.GetRR() {
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
	if len(roots.Map) == 0 {
		panic("could not resolve root hints")
	}
}

func processQuery(conn *net.UDPConn, address *net.UDPAddr, reader *tdns.PacketReader) {

	resolver := DNSResolver{DNSBufSize: 4000, DoIPv6: true}

	writer := tdns.NewMessageWriter(reader.Name(), reader.Type(), tdns.IN, math.MaxUint16)
	writer.DH.SetBitValue(tdns.RdMask, reader.DH().Bit(tdns.RdMask))
	writer.DH.SetBit(tdns.RaMask)
	writer.DH.SetBit(tdns.QrMask)
	writer.DH.Id = reader.DH().Id

	res, err := resolver.resolveAt(reader.Name(), reader.Type(), 0, tdns.MakeName(""), &roots)

	switch err.(type) {
	case nil:
		//for _, _ = range res.Auths {
		//writer.PutRR(tdns.Auths, &r.Name, r.Type, r.TTL, r.Class, r.Data)
		//}
		for _, r := range res.Intermediates {
			writer.PutRR(tdns.Answer, &r.Name, r.Type, r.TTL, r.Class, r.Data)
		}
		for _, r := range res.Answers {
			writer.PutRR(tdns.Answer, &r.Name, r.Type, r.TTL, r.Class, r.Data)
		}
	case NodataError:
		for _, r := range res.Auths {
			writer.PutRR(tdns.Authority, &r.Name, r.Type, r.TTL, r.Class, r.Data)
		}
		resolver.log("Nodata for %s|%s", reader.Name().String(), reader.Type())
	case NxdomainError:
		for _, r := range res.Auths {
			writer.PutRR(tdns.Authority, &r.Name, r.Type, r.TTL, r.Class, r.Data)
		}
		resolver.log("Nxdomain for %s|%s", reader.Name().String(), reader.Type())
		writer.DH.SetRcode(tdns.Nxdomain)
	case Servfail:
		resolver.log("Servfail for %s|%s", reader.Name().String(), reader.Type())
		writer.DH.SetRcode(tdns.Servfail)
	}
	conn.WriteTo(writer.Serialize(), address)

	resolver.log("Result of query for %s|%s %v %d/%d", reader.Name().String(), reader.Type(), err, len(res.Intermediates), len(res.Answers))
	for _, r := range res.Intermediates {
		resolver.log("%s", r.String())
	}
	for _, r := range res.Answers {
		resolver.log("%s", r.String())
	}

	resolver.log("Numqueries: %d", resolver.numQueries)
	resolver.log("BadServer: %s", badServers.Info())
	resolver.log("NegResultCache: %s", negResultCache.Info())
	resolver.log("RRCache: %s\n", rrCache.Info())
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
		if reader.DH().Bit(tdns.QrMask) == 1 {
			fmt.Printf("Received packet from %s was not a query\n", address)
			continue
		}
		go processQuery(conn, address.(*net.UDPAddr), reader)
	}
}

func main() {
	args := os.Args
	if len(args) != 2 && len(args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: tres name type\n")
		fmt.Fprintf(os.Stderr, "       tres ip:port\n")
		os.Exit(1)
	}

	go badServers.Run()
	go negResultCache.RunNeg()
	go rrCache.Run()

	resolveRootHints()
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
	if len(res.Answers) == 0 {
		fmt.Printf("No data for %s %s\n", args[1], args[2])
	} else {
		for _, r := range res.Intermediates {
			fmt.Printf("Intermediate %s\n", r.String())
		}
		for _, r := range res.Answers {
			fmt.Printf("Resolved %s\n", r.String())
		}
	}
	os.Exit(0)
}
