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
	"container/list"
	"fmt"
	"strings"
)

type (
	RCode   uint8
	Type    uint16
	Class   uint16
	Section uint16

	Label struct {
		Label []byte
	}
	Name struct {
		Name list.List
		key  string
	}

	// We keep the header in host native format. Code that write or reads it from the
	// wire is supposed to conversion
	Header struct {
		Id      uint16
		Flags   uint16
		QDCount uint16
		ANCount uint16
		NSCount uint16
		ARCount uint16
	}
)

const (
	HeaderLen   = 12
	MaxLabelLen = 63

	Noerror  RCode = 0
	Formerr        = 1
	Servfail       = 2
	Nxdomain       = 3
	Notimp         = 4
	Refused        = 5
	Notauth        = 9
	Badvers        = 16

	A      Type = 1
	NS          = 2
	CNAME       = 5
	SOA         = 6
	PTR         = 12
	MX          = 15
	TXT         = 16
	AAAA        = 28
	SRV         = 33
	NAPTR       = 35
	DS          = 43
	RRSIG       = 46
	NSEC        = 47
	DNSKEY      = 48
	NSEC3       = 50
	OPT         = 41
	IXFR        = 251
	AXFR        = 252
	ANY         = 255
	CAA         = 257

	IN Class = 1

	Question   Section = 0
	Answer             = 1
	Authority          = 2
	Additional         = 3

	QrMask     = 0x8000
	OpcodeMask = 0x7800
	AaMask     = 0x0400
	TcMask     = 0x0200
	RdMask     = 0x0100
	RaMask     = 0x0080
	UnusedMask = 0x0040
	AdMask     = 0x0020
	CdMask     = 0x0010
	RcodeMask  = 0x000f
)

func (h *Header) String() string {
	line1 := fmt.Sprintf("Header(Id=%#04x Fl=%#04x QD=%d AN=%d NS=%d AR=%0d ",
		h.Id, h.Flags, h.QDCount, h.ANCount, h.NSCount, h.ARCount)
	line2 := fmt.Sprintf("Qr=%d OpCode=%#x Aa=%d Tc=%d Rd=%d Ra=%d Un=%d, Ad=%d Cd=%d Rcode=%s)",
		h.Bit(QrMask),
		h.Opcode(),
		h.Bit(AaMask),
		h.Bit(TcMask),
		h.Bit(RdMask),
		h.Bit(RaMask),
		h.Bit(UnusedMask),
		h.Bit(AdMask),
		h.Bit(CdMask),
		h.Rcode())
	return line1 + line2
}

func (h *Header) SetBit(mask uint16) {
	h.Flags |= mask
}

func (h *Header) Bit(mask uint16) int {
	if h.Flags&mask != 0 {
		return 1
	} else {
		return 0
	}
}

func (h *Header) ClearBit(mask uint16) {
	h.Flags &^= mask
}

func (h *Header) SetBitValue(mask uint16, val int) {
	if val != 0 {
		h.SetBit(mask)
	} else {
		h.ClearBit(mask)
	}
}

func (h *Header) SetOpcode(val uint16) {
	h.Flags &^= OpcodeMask
	h.Flags |= OpcodeMask & (val << 11)
}

func (h *Header) Opcode() uint16 {
	return (h.Flags & OpcodeMask) >> 11
}

func (h *Header) SetRcode(val RCode) {
	h.Flags &^= RcodeMask
	h.Flags |= RcodeMask & uint16(val)
}

func (h *Header) Rcode() RCode {
	return RCode(h.Flags & RcodeMask)
}

func NewLabel(data string) *Label {

	if len(data) > MaxLabelLen {
		return nil
	}
	label := new(Label)
	label.Label = []byte(data)
	return label
}

func (l *Label) Len() int {
	return len(l.Label)
}

func (l *Label) Empty() bool {
	return len(l.Label) == 0
}

func charcmp(a, b byte) int {
	if a >= 0x61 && a <= 0x7A {
		a -= 0x20
	}
	if b >= 0x61 && b <= 0x7A {
		b -= 0x20
	}
	if a < b {
		return -1
	} else if a > b {
		return 1
	} else {
		return 0
	}
}

func (l *Label) Less(b *Label) bool {
	for i := 0; i < len(l.Label) && i < len(b.Label); i++ {
		if c := charcmp(l.Label[i], b.Label[i]); c < 0 {
			return true
		} else if c > 0 {
			return false
		}
	}
	return len(l.Label) < len(b.Label)
}

func (l *Label) Equals(b *Label) bool {
	return !l.Less(b) && !b.Less(l)
}

func (l *Label) String() string {
	var b strings.Builder
	for _, a := range l.Label {
		if a <= 0x20 || a >= 0x7f { // RFC 4343
			_, _ = fmt.Fprintf(&b, "\\%03d", a)
		} else {
			if a == '.' || a == '\\' {
				b.WriteByte(byte('\\'))
			}
			b.WriteByte(a)
		}
	}
	return b.String()
}

func NewName(labels []string) *Name {
	n := new(Name)
	for _, l := range labels {
		n.Name.PushBack(NewLabel(l))
	}
	return n
}

func NewNameFromTail(labels *list.Element) *Name {
	n := new(Name)
	for ; labels != nil; labels = labels.Next() {
		l := labels.Value.(*Label)
		n.Name.PushBack(l)
	}
	return n
}

func (n *Name) K() string {
	if n.key == "" {
		n.key = n.string()
	}
	return n.key
}

func (n *Name) String() string {
	return n.K()
}

func (n *Name) string() string {
	if n.Empty() {
		return "."
	}
	var b strings.Builder
	for e := n.Name.Front(); e != nil; e = e.Next() {
		b.WriteString(e.Value.(*Label).String())
		b.WriteString(".")
	}
	return b.String()
}

func (n *Name) Bytes() []byte {
	var b bytes.Buffer

	for e := n.Name.Front(); e != nil; e = e.Next() {
		l := e.Value.(*Label)
		XfrUInt8(&b, uint8(l.Len()))
		XfrBlob(&b, l.Label)
	}
	XfrUInt8(&b, uint8(0))
	return b.Bytes()
}

func (n *Name) Len() int {
	return n.Name.Len()
}

func (n *Name) Empty() bool {
	return n.Name.Len() == 0
}

func (n *Name) Less(b *Name) bool {
	for i1, i2 := n.Name.Front(), b.Name.Front(); i1 != nil && i2 != nil; i1, i2 = i1.Next(), i2.Next() {
		v1 := i1.Value.(*Label)
		v2 := i2.Value.(*Label)
		if v1.Less(v2) {
			return true
		} else if v2.Less(v1) {
			return false
		}
	}
	return n.Name.Len() < b.Name.Len()
}

func (n *Name) Equals(b *Name) bool {
	return !n.Less(b) && !b.Less(n)
}

func (n *Name) Append(b *Name) {
	for e := b.Name.Front(); e != nil; e = e.Next() {
		n.Name.PushBack(e.Value.(*Label))
	}
	n.key = n.string()
}

func (n *Name) PushBack(l *Label) {
	n.Name.PushBack(l)
	n.key = n.string()
}

func (n *Name) IsPartOf(root *Name) bool {
	r := root.Name.Back()
	us := n.Name.Back()
	for {
		if r == nil {
			return true
		}
		if us == nil {
			return false
		}
		usValue := us.Value.(*Label)
		themValue := r.Value.(*Label)

		if usValue.Equals(themValue) {
			r = r.Prev()
			us = us.Prev()
		} else {
			return false
		}
	}
}

func MakeName(str string) *Name {
	a := strings.Split(str, ".")
	b := make([]string, 0, len(a))
	for _, aa := range a {
		if len(aa) > 0 {
			b = append(b, aa)
		}
	}
	return NewName(b)
}

var (
	typemap1 = map[string]Type{
		"A":      A,
		"NS":     NS,
		"CNAME":  CNAME,
		"SOA":    SOA,
		"PTR":    PTR,
		"MX":     MX,
		"TXT":    TXT,
		"AAAA":   AAAA,
		"SRV":    SRV,
		"NAPTR":  NAPTR,
		"DS":     DS,
		"RRSIG":  RRSIG,
		"NSEC":   NSEC,
		"DNSKEY": DNSKEY,
		"NSEC3":  NSEC3,
		"OPT":    OPT,
		"IXFR":   IXFR,
		"AXFR":   AXFR,
		"ANY":    ANY,
		"CAA":    CAA,
	}

	typemap2 map[Type]string

	sectionmap1 = map[string]Section{
		"Question":   Question,
		"Answer":     Answer,
		"Authority":  Authority,
		"Additional": Additional,
	}

	sectionmap2 map[Section]string

	rcodemap1 = map[string]RCode{
		"Noerror":  Noerror,
		"Formerr":  Formerr,
		"Servfail": Servfail,
		"Nxdomain": Nxdomain,
		"Notimp":   Notimp,
		"Refused":  Refused,
		"Notauth":  Notauth,
		"Badvers":  Badvers,
	}

	rcodemap2 map[RCode]string
)

func init() {
	typemap2 = make(map[Type]string)
	for k, v := range typemap1 {
		typemap2[v] = k
	}
	sectionmap2 = make(map[Section]string)
	for k, v := range sectionmap1 {
		sectionmap2[v] = k
	}
	rcodemap2 = make(map[RCode]string)
	for k, v := range rcodemap1 {
		rcodemap2[v] = k
	}
}

func MakeType(str string) Type {
	ret := typemap1[str]
	if ret == 0 {
		panic(fmt.Sprintf("Unknown type: %s", str))
	}
	return ret
}

func (t Type) String() string {
	ret := typemap2[t]
	if ret == "" {
		return fmt.Sprintf("%#x", t)
	}
	return ret
}

func (s Section) String() string {
	ret := sectionmap2[s]
	if ret == "" {
		return fmt.Sprintf("%#x", s)
	}
	return ret
}

func (r RCode) String() string {
	ret := rcodemap2[r]
	if ret == "" {
		return fmt.Sprintf("%#x", r)
	}
	return ret
}
