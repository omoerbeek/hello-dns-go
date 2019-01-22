package dnsstorage

import (
	"container/list"
	"fmt"
	"strings"
)

// DNSLabel
type (
	RCode uint8
	DNSType uint16
	DNSClass uint16
	DNSSection uint16

	DNSLabel struct {
		Label []byte
	}
	DNSName struct {
		Name list.List
	}

	// We keep the header in host native format. Code that write or reads it from the
	// wire is supposed to conversion
	DNSHeader struct {
		Id      uint16
		Second  uint16
		QDCount uint16
		ANCount uint16
		NSCount uint16
		ARCount uint16
	}
)

const (
	Noerror  RCode = 0
	Formerr        = 1
	Servfail       = 2
	Nxdomain       = 3
	Notimp         = 4
	Refused        = 5
	Notauth        = 9
	Badvers        = 16

	A      DNSType = 1
	NS             = 2
	CNAME          = 5
	SOA            = 6
	PTR            = 12
	MX             = 15
	TXT            = 16
	AAAA           = 28
	SRV            = 33
	NAPTR          = 35
	DS             = 43
	RRSIG          = 46
	NSEC           = 47
	DNSKEY         = 48
	NSEC3          = 50
	OPT            = 41
	IXFR           = 251
	AXFR           = 252
	ANY            = 255
	CAA            = 257

	IN DNSClass = 1
	CH          = 3

	Question   DNSSection = 0
	Answer                = 1
	Authority             = 2
	Additional            = 3

	QR_MASK     = 0x8000
	OPCODE_MASK = 0x7800
	AA_MASK     = 0x0400
	TC_MASK     = 0x0200
	RD_MASK     = 0x0100
	RA_MASK     = 0x0080
	UNUSED_MASK = 0x0040
	AD_MASK     = 0x0020
	CD_MASK     = 0x0010
	RCODE_MASK  = 0x000f

)

func (h *DNSHeader) SetBit( mask uint16) {
	h.Second |= mask
}

func (h *DNSHeader) ClearHeaderBit(mask uint16) {
	h.Second &^= mask
}

func (h *DNSHeader) SetOpcode(val uint16) {
	h.Second &^= OPCODE_MASK
	h.Second |= OPCODE_MASK & (val << 12)
}

func (h *DNSHeader) GetOpcode(val uint16) uint16 {
	return (h.Second & OPCODE_MASK) >> 12
}

func (h *DNSHeader) SetRcode(val uint16) {
	h.Second &^= RCODE_MASK
	h.Second |= (RCODE_MASK & val) << 0
}

func (h *DNSHeader) GetRcode(val uint16) uint16 {
	return (h.Second & RCODE_MASK) >> 0
}

func NewDNSLabel(data string) *DNSLabel {

	if len(data) > 63 {
		return nil
	}
	label := new(DNSLabel)
	label.Label = []byte(data)
	return label
}

func (l *DNSLabel) Len() int {
	return len(l.Label)
}

func (l *DNSLabel) Empty() bool {
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

func (a *DNSLabel) Less(b *DNSLabel) bool {
	for i := 0; i < len(a.Label) && i < len(b.Label); i++ {
		if c := charcmp(a.Label[i], b.Label[i]); c < 0 {
			return true
		} else if c > 0 {
			return false
		}
	}
	return len(a.Label) < len(b.Label)
}

func (a *DNSLabel) Equals(b *DNSLabel) bool {
	return a.Less(b) || b.Less(a)
}

func (a *DNSLabel) String() string {
	var b strings.Builder
	for _, a := range (a.Label) {
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

func NewDNSName(labels []string) *DNSName {
	n := new(DNSName)
	for _, l := range (labels) {
		n.Name.PushBack(NewDNSLabel(l))
	}
	return n
}

func (n *DNSName) Len() int {
	return n.Name.Len()
}

func (n *DNSName) Empty() bool {
	return n.Name.Len() == 0
}

func (a *DNSName) Less(b *DNSName) bool {
	for i1, i2 := a.Name.Front(), b.Name.Front(); i1 != nil && i2 != nil; i1, i2 = i1.Next(), i2.Next() {
		v1 := i1.Value.(*DNSLabel)
		v2 := i2.Value.(*DNSLabel)
		if v1.Less(v2) {
			return true
		} else if v2.Less(v1) {
			return false
		}
	}
	return a.Name.Len() < b.Name.Len()
}

func (a *DNSName) Equals(b *DNSName) bool {
	return a.Less(b) || b.Less(a)
}

func (a *DNSName) String() string {
	if a.Empty() {
		return "."
	}
	var b strings.Builder
	for e := a.Name.Front(); e != nil; e = e.Next() {
		b.WriteString(e.Value.(*DNSLabel).String())
		b.WriteString(".")
	}
	return b.String()
}

func MakeDNSName(str string) *DNSName {
	/*if len(str) == 0 {
		return NewDNSName([]string{})
	}*/
	a := strings.Split(str, ".")
	b := make([]string, 0, len(a))
	for _, aa := range a {
		if len(aa) > 0 {
			b = append(b, aa)
		}
	}
	return NewDNSName(b)
}

func MakeDNSType(str string) DNSType {
	switch str {
	case "A":
		return A
	default: panic("NYI")
	}
}
