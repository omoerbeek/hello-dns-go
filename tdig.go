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

	dn := tdns.MakeDNSName(args[1])
	dtype := tdns.MakeDNSType(args[2])

	fmt.Println(dn, dtype)

	conn, err := net.Dial("udp", args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not contact %s: %s", args[3], err)
	}
	writer := tdns.NewDNSMessageWriter(dn, dtype, tdns.IN, math.MaxUint16)
	writer.DH.SetBit(tdns.RdMask)

	// Use a good random source out of principle
	r, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint16+1))
	writer.DH.Id = uint16(r.Int64())

	msg := writer.Serialize()
	conn.Write(msg)

	data := make([]byte, math.MaxUint16)
	nread, err := conn.Read(data)
	fmt.Printf("Read %d: %s %s", nread, err, data)
}
