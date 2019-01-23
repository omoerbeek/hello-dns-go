package main

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"net"
	"os"

	"tdns"
)

func main() {
	args := os.Args
	if len(args) != 4 {
		fmt.Fprintf(os.Stderr, "Usage: tdig name type ip:port\n")
		os.Exit(1)
	}

	dn := tdns.MakeName(args[1])
	dtype := tdns.MakeType(args[2])

	fmt.Println(dn, dtype)

	conn, err := net.Dial("udp", args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not contact %s: %s\n", args[3], err)
		os.Exit(1)
	}
	writer := tdns.NewDNSMessageWriter(dn, dtype, tdns.IN, math.MaxUint16)
	writer.DH.SetBit(tdns.RdMask)
	writer.SetEDNS(4000, false, tdns.Noerror);

	// Use a good random source out of principle
	r, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint16+1))
	writer.DH.Id = uint16(r.Int64())

	msg := writer.Serialize()
	if _, err := conn.Write(msg); err != nil {
		fmt.Fprintf(os.Stderr, "Could not write query: %s\n", err)
		os.Exit(1)
	}

	data := make([]byte, math.MaxUint16)
	var n int
	if n, err = conn.Read(data); err != nil {
		fmt.Fprintf(os.Stderr, "Could not read answer: %s\n", err)
		os.Exit(1)
	}

	reader, err := tdns.NewMessagReader(data, n)
	fmt.Printf("Read %d bytes %v %v\n", n, reader, err)

	var rrsection tdns.Section
	var name *tdns.Name
	var dnstype tdns.Type
	var ttl uint32
	var rr tdns.RRGen
	for reader.GetRR(&rrsection, &name, &dnstype, &ttl, &rr) {
		fmt.Printf("section=%v name=%v type=%v ttl=%v data=%v\n", rrsection, name, dnstype, ttl, rr)
	}
	os.Exit(0)
}
