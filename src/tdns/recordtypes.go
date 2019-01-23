package tdns

import (
	"fmt"
	"net"
)

type RRGen interface {
	Gen(r *MessageReader, l uint16)
}

type UnknownGen struct {
	Data []byte
}

func (a *UnknownGen) Gen(r * MessageReader, l uint16) {
	a.Data = r.getBlob(l,nil)
}

func (a *UnknownGen) String() string {
	return fmt.Sprintf("%x", a.Data)
}


type AGen struct {
	IP net.IP
}

func (a *AGen) Gen(r * MessageReader, l uint16) {
	data := r.getUint32(nil)
	a.IP = []byte { byte(data >> 24), byte(data >> 16), byte(data >> 8), byte(data) }
}

func (a *AGen) String() string {
	return a.IP.String()
}

type AAAAGen struct {
	IP net.IP
}

func (a *AAAAGen) Gen(r * MessageReader, l uint16) {
	a.IP = r.getBlob(16,nil)
}

func (a *AAAAGen) String() string {
	return a.IP.String()
}

type NSGen struct {
	NSName *Name
}

func (a *NSGen) Gen(r * MessageReader, l uint16) {
	a.NSName = r.getName(nil)
}

func (a *NSGen) String() string {
	return a.NSName.String()
}