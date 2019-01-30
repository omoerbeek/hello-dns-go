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

type RRec struct {
	Section Section
	Name    Name
	Type    Type
	TTL     uint32
	Class   Class
	Data    RRGen
}

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
	namemap map[string]uint16
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
			tname := NewNameFromTail(e);
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
			act := NewMessageWriter(&w.name, w.dnstype, w.class, HeaderLen + w.payload.Len())
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
	w.payload.Truncate(current);
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
	bytes := data.ToMessage(w)
	XfrUInt16(w.payload, uint16(len(bytes)))
	XfrBlob(w.payload, bytes)

	if w.payload.Len() > w.maxsize {
		// It did not fit, reset and report
		w.payload.Truncate(current)
		return fmt.Errorf("Message did not fit")
	}
	switch s {
	case Question:
		return fmt.Errorf("Can't add questions to a DNS Message with putRR")
	case Answer:
		if w.DH.NSCount > 0 || w.DH.ARCount > 0 {
			return fmt.Errorf("Can't add answer RRs out of order to a DNS Messa ge")
		}
		w.DH.ANCount++
	case Authority:
		if w.DH.ARCount > 0 {
			return fmt.Errorf("Can't add authority RRs out of order to a DNS Message")
		}
		w.DH.NSCount++
	case Additional:
		w.DH.ARCount++
	}
	return nil
}

type MessageReader struct {
	DH          Header
	Name        Name
	Type        Type
	Class       Class
	bufsize     uint16
	doBit       bool
	ednsVersion uint8
	haveEDNS    bool
	payload     []byte
	payloadpos  uint16
	rrpos       uint16
	endofrecord uint16 // needed?
}

func (r *MessageReader) String() string {
	header := r.DH.String()
	if r.haveEDNS {
		b := 0
		if r.doBit {
			b = 1
		}
		header += fmt.Sprintf(" doBit=%d EDNSversion=%d bufsize=%d", b, r.ednsVersion, r.bufsize)
	}
	return header
}

func NewMessagReader(data []byte, length int) (*MessageReader, error) {
	if len(data) < HeaderLen || length < HeaderLen || len(data) < length {
		return nil, io.ErrShortBuffer
	}
	r := new(MessageReader)
	err := r.Read(data, length)
	return r, err
}

func (r *MessageReader) Read(data []byte, length int) error {
	reader := bytes.NewReader(data)
	err := binary.Read(reader, binary.BigEndian, &r.DH)
	if err != nil {
		return err
	}
	r.payload = data[HeaderLen:length]

	if r.DH.QDCount > 0 {
		r.Name = *r.getName(nil)
		r.Type = Type(r.getUint16(nil))
		r.Class = Class(r.getUint16(nil))
	}

	if r.DH.ARCount > 0 {
		nowpos := r.payloadpos
		r.skipRRs(int(r.DH.ANCount + r.DH.NSCount + r.DH.ARCount - 1))
		if r.getUint8(nil) == 0 && Type(r.getUint16(nil)) == OPT {
			r.bufsize = r.getUint16(nil)
			r.getUint8(nil)
			r.ednsVersion = r.getUint8(nil)
			r.doBit = false
			flags := r.getUint8(nil)
			if flags&0x80 != 0 {
				r.doBit = true
			}
			r.getUint8(nil)
			r.getUint16(nil)
			r.haveEDNS = true
		}
		r.payloadpos = nowpos
	}
	return err
}

func (r *MessageReader) skipRRs(num int) {
	for i := 0; i < num; i++ {
		r.getName(nil)
		r.payloadpos += 8 // type, class , ttl
		l := r.getUint16(nil)
		r.payloadpos += l
		if r.payloadpos > uint16(len(r.payload)) {
			// XXX handle error!
		}
	}
}


func (r *MessageReader) GetRR() (rrec *RRec) {
	if r.payloadpos == uint16(len(r.payload)) {
		return nil
	}
	rrec = new(RRec)
	if r.rrpos < r.DH.ANCount {
		rrec.Section = Answer
	} else if r.rrpos < r.DH.ANCount+r.DH.NSCount {
		rrec.Section = Authority
	} else {
		rrec.Section = Additional
	}

	r.rrpos++

	rrec.Name = *r.getName(nil)
	rrec.Type = Type(r.getUint16(nil))
	rrec.Class = Class(r.getUint16(nil))
	rrec.TTL = r.getUint32(nil)
	l := r.getUint16(nil)
	r.endofrecord = r.payloadpos + l

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
	default:
		result = new(UnknownGen)
	}
	result.Gen(r, l)
	rrec.Data = result

	return rrec
}

func (r *MessageReader) getUint8(pos *uint16) uint8 {
	if pos == nil {
		pos = &r.payloadpos
	}
	ret := r.payload[*pos]
	*pos += 1
	return ret

}

func (r *MessageReader) getUint16(pos *uint16) uint16 {
	if pos == nil {
		pos = &r.payloadpos
	}
	ret := binary.BigEndian.Uint16(r.payload[*pos : *pos+2])
	*pos += 2
	return ret
}

func (r *MessageReader) getUint32(pos *uint16) uint32 {
	if pos == nil {
		pos = &r.payloadpos
	}
	ret := binary.BigEndian.Uint32(r.payload[*pos : *pos+4])
	*pos += 4
	return ret
}

func (r *MessageReader) getBlob(size uint16, pos *uint16) []byte {
	if pos == nil {
		pos = &r.payloadpos
	}
	data := make([]byte, size)
	copy(data, r.payload[*pos:*pos+size])
	*pos += size
	return data
}

func (r *MessageReader) getName(pos *uint16) *Name {
	ret := new(Name)
	if pos == nil {
		pos = &r.payloadpos
	}
	for {
		labellen := uint16(r.getUint8(pos))
		if labellen&0xc0 != 0 {
			labellen2 := uint16(r.getUint8(pos))
			newpos := ((labellen &^ 0xc0) << 8) | labellen2
			newpos -= HeaderLen
			if newpos < *pos {
				ret.Append(r.getName(&newpos))
				return ret
			} else {
				panic("forward compression")
			}
		}
		if labellen == 0 {
			break
		}
		label := NewLabel(string(r.getBlob(labellen, pos))) // XXX string vs []byte
		ret.PushBack(label)
	}
	return ret
}
