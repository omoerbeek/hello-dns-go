package main

import (
	"dnsmessages"
	"fmt"
	"net"
	"os"
	"dnsstorage"
	"math/rand"
)

func main() {
	args := os.Args
	if len(args) != 4 {
		fmt.Fprintf(os.Stderr, "Usage: tdig name type ip:port\n")
		os.Exit(1)
	}

	dn := dnsstorage.MakeDNSName(args[1]);
	dtype := dnsstorage.MakeDNSType(args[2]);

	fmt.Println(dn, dtype)

	conn, err := net.Dial("udp", args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not contact %s: %s", args[3], err)
	}
	writer := dnsmessages.NewDNSMessageWriter(dn, dtype, dnsstorage.IN, 8192);
	writer.DH.SetBit(dnsstorage.RD_MASK)
	writer.DH.Id = uint16(rand.Int())
	msg := writer.Serialize();
	conn.Write(msg)

	data := make([]byte, 65535)
	nread, err := conn.Read(data)
	fmt.Printf("Read %d: %s %s", nread, err, data)
}
