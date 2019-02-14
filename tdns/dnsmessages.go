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

package tdns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

type (
	RRec struct {
		Section Section
		Name    Name
		Type    Type
		TTL     uint32
		Class   Class
		Data    RRGen
	}

	ResolveResult struct {
		Auths         []*RRec
		Answers       []*RRec
		Intermediates []*RRec
	}
)

func (r *RRec) String() string {
	return fmt.Sprintf("%-30s\t%d\t%v\t%v", &r.Name, r.TTL, r.Type, r.Data)
}

func XfrUInt32(b *bytes.Buffer, val uint32) {
	binary.Write(b, binary.BigEndian, val)
}

func XfrUInt16(b *bytes.Buffer, val uint16) {
	binary.Write(b, binary.BigEndian, val)
}

func XfrUInt8(b *bytes.Buffer, val uint8) {
	b.WriteByte(val)
}

func XfrBlob(b *bytes.Buffer, data []byte) {
	b.Write(data)
}

type MessageWriter struct {
	DH       Header
	name     Name
	dnstype  Type
	class    Class
	haveEDNS bool
	doBit    bool
	erCode   RCode
	payload  *bytes.Buffer
	maxsize  int
	namemap  map[string]uint16
}

func NewMessageWriter(name *Name, dnstype Type, class Class, maxsize int) *MessageWriter {
	r := new(MessageWriter)
	r.payload = new(bytes.Buffer)
	r.maxsize = maxsize - HeaderLen
	r.payload.Grow(r.maxsize)
	r.name = *name
	r.dnstype = dnstype
	r.class = class
	r.resetRRs()
	return r
}

func (w *MessageWriter) resetRRs() {
	w.namemap = make(map[string]uint16)
	w.payload.Reset()
	w.DH.QDCount = 1
	w.XfrName(w.payload, &w.name, true)
	XfrUInt16(w.payload, uint16(w.dnstype))
	XfrUInt16(w.payload, uint16(w.class))
}

func (w *MessageWriter) XfrName(b *bytes.Buffer, name *Name, compress bool) {

	for e := name.Name.Front(); e != nil; e = e.Next() {
		if compress {
			tname := NewNameFromTail(e)
			pos, ok := w.namemap[tname.K()]
			if ok {
				// we have a tail we can use
				XfrUInt8(b, uint8((pos>>8)|0xc0))
				XfrUInt8(b, uint8(pos&0xff))
				//fmt.Printf("%s map is %v\n", name.String(), w.namemap)
				return
			} else {
				pos := w.payload.Len()
				if w.payload != b {
					pos += b.Len() + 2
				}
				w.namemap[tname.K()] = uint16(pos + HeaderLen)
			}
		}
		l := e.Value.(*Label)
		XfrUInt8(b, uint8(l.Len()))
		XfrBlob(b, l.Label)
	}
	XfrUInt8(b, uint8(0))
	if compress {
		//fmt.Printf("%s map is %v\n", name.String(), w.namemap)
	}
}

func (w *MessageWriter) bytes() []byte {
	buf := new(bytes.Buffer)
	buf.Grow(HeaderLen + w.payload.Len())

	// Write header and then payload
	binary.Write(buf, binary.BigEndian, w.DH)
	w.payload.WriteTo(buf)
	return buf.Bytes()
}

func (w *MessageWriter) Serialize() []byte {
	if w.haveEDNS {
		ok := w.putEDNS(w.maxsize+HeaderLen, w.erCode, w.doBit)
		if !ok {
			// Handle does not fit case by just returning an EDNS record with the len we would have needed
			act := NewMessageWriter(&w.name, w.dnstype, w.class, HeaderLen+w.payload.Len())
			act.DH = w.DH
			act.putEDNS(HeaderLen+w.payload.Len(), w.erCode, w.doBit)
			return act.bytes()
		}
	}
	return w.bytes()
}

func (w *MessageWriter) putEDNS(bufsize int, ercode RCode, doBit bool) bool {
	current := w.payload.Len()
	XfrUInt8(w.payload, 0)
	XfrUInt16(w.payload, OPT) // 'root' Name, our type
	XfrUInt16(w.payload, uint16(bufsize))
	XfrUInt8(w.payload, uint8(ercode)>>4)
	XfrUInt8(w.payload, 0)
	var bitval uint8 = 0
	if doBit {
		bitval = 0x80
	}
	XfrUInt8(w.payload, bitval)
	XfrUInt8(w.payload, 0)
	XfrUInt16(w.payload, 0)
	w.DH.ARCount++
	if w.payload.Len() <= w.maxsize {
		return true
	}
	// It did not fit, reset and report
	w.payload.Truncate(current)
	return false
}

func (w *MessageWriter) SetEDNS(newsize int, doBit bool, rcode RCode) {
	if newsize > HeaderLen {
		w.maxsize = newsize - HeaderLen
	}
	w.doBit = doBit
	w.erCode = rcode
	w.haveEDNS = true
}

func (w *MessageWriter) PutRR(s Section, name *Name, dnstype Type, ttl uint32, class Class, data RRGen) error {
	current := w.payload.Len()

	w.XfrName(w.payload, name, true)
	XfrUInt16(w.payload, uint16(dnstype))
	XfrUInt16(w.payload, uint16(class))
	XfrUInt32(w.payload, ttl)
	rawbytes := data.ToMessage(w)
	XfrUInt16(w.payload, uint16(len(rawbytes)))
	XfrBlob(w.payload, rawbytes)

	if w.payload.Len() > w.maxsize {
		// It did not fit, reset and report
		w.payload.Truncate(current)
		return fmt.Errorf("message did not fit")
	}
	switch s {
	case Question:
		return fmt.Errorf("can'timestamp add questions to a DNS Message with putRR")
	case Answer:
		if w.DH.NSCount > 0 || w.DH.ARCount > 0 {
			return fmt.Errorf("can'timestamp add answer RRs out of order to a DNS Message")
		}
		w.DH.ANCount++
	case Authority:
		if w.DH.ARCount > 0 {
			return fmt.Errorf("can'timestamp add authority RRs out of order to a DNS Message")
		}
		w.DH.NSCount++
	case Additional:
		w.DH.ARCount++
	}
	return nil
}

type MessageReaderInterface interface {
	Reset()
	GetRR() (rrec *RRec)
	DH() *Header
	Name() *Name
	Type() Type
	Class() Class
	FromCache() bool
	Answers() bool
}

type PacketReader struct {
	dh          Header
	name        *Name
	dnstype     Type
	class       Class
	bufsize     uint16
	doBit       bool
	ednsVersion uint8
	haveEDNS    bool
	payload     []byte
	payloadpos  uint16
	rrpos       uint16
	data        []byte
	length      int
}

func (p *PacketReader) FromCache() bool {
	return false
}

func (p *PacketReader) DH() *Header {
	return &p.dh
}

func (p *PacketReader) Name() *Name {
	return p.name
}

func (p *PacketReader) Type() Type {
	return p.dnstype
}

func (p *PacketReader) Class() Class {
	return p.class
}

func (p *PacketReader) Answers() bool {
	return true
}

func (p *PacketReader) String() string {
	header := p.dh.String()
	if p.haveEDNS {
		b := 0
		if p.doBit {
			b = 1
		}
		header += fmt.Sprintf(" doBit=%d EDNSversion=%d bufsize=%d", b, p.ednsVersion, p.bufsize)
	}
	return header
}

func NewMessagReader(data []byte, length int) (*PacketReader, error) {
	if len(data) < HeaderLen || length < HeaderLen || len(data) < length {
		return nil, io.ErrShortBuffer
	}
	r := new(PacketReader)
	err := r.Read(data, length)
	return r, err
}

func (p *PacketReader) Reset() {
	if err := p.Read(p.data, p.length); err != nil {
		panic(err.Error())
	}
}

func (p *PacketReader) Read(data []byte, length int) error {
	p.data = data
	p.length = length
	reader := bytes.NewReader(data)
	err := binary.Read(reader, binary.BigEndian, &p.dh)
	if err != nil {
		return err
	}
	p.payload = data[HeaderLen:length]
	p.payloadpos = 0
	p.rrpos = 0

	if p.dh.QDCount > 0 {
		p.name = p.getName(nil)
		p.dnstype = Type(p.getUint16(nil))
		p.class = Class(p.getUint16(nil))
	}

	if p.dh.ARCount > 0 {
		nowpos := p.payloadpos
		p.skipRRs(int(p.dh.ANCount + p.dh.NSCount + p.dh.ARCount - 1))
		if p.getUint8(nil) == 0 && Type(p.getUint16(nil)) == OPT {
			p.bufsize = p.getUint16(nil)
			p.getUint8(nil)
			p.ednsVersion = p.getUint8(nil)
			p.doBit = false
			flags := p.getUint8(nil)
			if flags&0x80 != 0 {
				p.doBit = true
			}
			p.getUint8(nil)
			p.getUint16(nil)
			p.haveEDNS = true
		}
		p.payloadpos = nowpos
	}
	return err
}

func (p *PacketReader) skipRRs(num int) {
	for i := 0; i < num; i++ {
		p.getName(nil)
		p.payloadpos += 8 // type, class , ttl
		l := p.getUint16(nil)
		p.payloadpos += l
		if p.payloadpos > uint16(len(p.payload)) {
			// XXX handle error!
		}
	}
}

func (p *PacketReader) GetRR() (rrec *RRec) {
	if p.payloadpos == uint16(len(p.payload)) {
		return nil
	}
	rrec = new(RRec)
	if p.rrpos < p.dh.ANCount {
		rrec.Section = Answer
	} else if p.rrpos < p.dh.ANCount+p.dh.NSCount {
		rrec.Section = Authority
	} else {
		rrec.Section = Additional
	}

	p.rrpos++

	rrec.Name = *p.getName(nil)
	rrec.Type = Type(p.getUint16(nil))
	rrec.Class = Class(p.getUint16(nil))
	rrec.TTL = p.getUint32(nil)
	l := p.getUint16(nil)
	//p.endofrecord = p.payloadpos + l

	var result RRGen
	switch rrec.Type {
	case A:
		result = new(AGen)
	case AAAA:
		result = new(AAAAGen)
	case NS:
		result = new(NSGen)
	case CNAME:
		result = new(CNAMEGen)
	case SOA:
		result = new(SOAGen)
	case MX:
		result = new(MXGen)
	default:
		result = new(UnknownGen)
	}
	result.Gen(p, l)
	rrec.Data = result

	return rrec
}

func (p *PacketReader) getUint8(pos *uint16) uint8 {
	if pos == nil {
		pos = &p.payloadpos
	}
	ret := p.payload[*pos]
	*pos += 1
	return ret
}

func (p *PacketReader) getUint16(pos *uint16) uint16 {
	if pos == nil {
		pos = &p.payloadpos
	}
	ret := binary.BigEndian.Uint16(p.payload[*pos : *pos+2])
	*pos += 2
	return ret
}

func (p *PacketReader) getUint32(pos *uint16) uint32 {
	if pos == nil {
		pos = &p.payloadpos
	}
	ret := binary.BigEndian.Uint32(p.payload[*pos : *pos+4])
	*pos += 4
	return ret
}

func (p *PacketReader) getBlob(size uint16, pos *uint16) []byte {
	if pos == nil {
		pos = &p.payloadpos
	}
	data := make([]byte, size)
	copy(data, p.payload[*pos:*pos+size])
	*pos += size
	return data
}

func (p *PacketReader) getName(pos *uint16) *Name {
	ret := new(Name)
	if pos == nil {
		pos = &p.payloadpos
	}
	for {
		labellen := uint16(p.getUint8(pos))
		if labellen&0xc0 != 0 {
			labellen2 := uint16(p.getUint8(pos))
			newpos := ((labellen &^ 0xc0) << 8) | labellen2
			newpos -= HeaderLen
			if newpos < *pos {
				ret.Append(p.getName(&newpos))
				return ret
			} else {
				panic("forward compression")
			}
		}
		if labellen == 0 {
			break
		}
		label := NewLabel(string(p.getBlob(labellen, pos))) // XXX string vs []byte
		ret.PushBack(label)
	}
	return ret
}
