package dnsmessages

import (
	"dnsstorage"
	"encoding/binary"
)

type DNSMessageWriter struct {
	DH         dnsstorage.DNSHeader
	name       *dnsstorage.DNSName
	dnsqtype   dnsstorage.DNSType
	class      dnsstorage.DNSClass
	payload    []byte
	payloadpos int
}

func NewDNSMessageWriter(name *dnsstorage.DNSName, dnstype dnsstorage.DNSType, class dnsstorage.DNSClass, maxsize int) *DNSMessageWriter {
	r := new(DNSMessageWriter)
	r.payload = make([]byte, maxsize-12, maxsize-12)
	r.name = name
	r.dnsqtype = dnstype
	r.class = class
	r.resetRRs()
	return r;
}

func (w *DNSMessageWriter) resetRRs() {
	//w.payload = w.payload[0:0]
	w.payloadpos = 0;
	w.DH.QDCount = 1
	w.XfrName(w.name, false)
	w.XfrUInt16(uint16(w.dnsqtype))
	w.XfrUInt16(uint16(w.class))
}

func (w *DNSMessageWriter) XfrUInt16(val uint16) {
	binary.BigEndian.PutUint16(w.payload[w.payloadpos:], val)
	w.payloadpos += 2;
}

func (w *DNSMessageWriter) XfrUInt8(val uint8) {
	w.payload[w.payloadpos] = val
	w.payloadpos += 1;
}

func (w *DNSMessageWriter) XfrBlob(data []byte) {
	copy(w.payload[w.payloadpos:], data)
	w.payloadpos += len(data);
}

func (w *DNSMessageWriter) XfrName(a *dnsstorage.DNSName, compress bool) {
	for e := a.Name.Front(); e != nil; e = e.Next() {
		l := e.Value.(*dnsstorage.DNSLabel)
		w.XfrUInt8(uint8(l.Len()))
		w.XfrBlob(l.Label)
	}
}

func (w *DNSMessageWriter) serializeHeader(hbytes []byte) {
	i := 0
	binary.BigEndian.PutUint16(hbytes[i:], w.DH.Id)
	i += 2
	binary.BigEndian.PutUint16(hbytes[i:], w.DH.Second)
	i += 2
	binary.BigEndian.PutUint16(hbytes[i:], w.DH.QDCount)
	i += 2
	binary.BigEndian.PutUint16(hbytes[i:], w.DH.ANCount)
	i += 2
	binary.BigEndian.PutUint16(hbytes[i:], w.DH.NSCount)
	i += 2
	binary.BigEndian.PutUint16(hbytes[i:], w.DH.ARCount)
}

func (w *DNSMessageWriter) Serialize() []byte {
	ret := make([]byte, 12 + len(w.payload))
	w.serializeHeader(ret);
	copy(ret[12:], w.payload);
	return ret;
}

