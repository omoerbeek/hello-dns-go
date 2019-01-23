package tdns

import "testing"

func TestDNSLabel(t *testing.T) {
	l1 := NewDNSLabel("aap")
	if l1 == nil {
		t.Errorf("Label is nil")
	}
	l2 := NewDNSLabel("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;lkl;kaaaaaaaap")
	if l2 != nil {
		t.Error("Label is not nil")
	}
	if l2 != nil {
		t.Error("Label is not nil")
	}

	l3 := NewDNSLabel("\000123")
	if l3.Len() != 4 {
		t.Errorf("Length is not 4 but %d", l3.Len())
	}

	tests1 := []struct {
		a, b string
		x, y bool
	}{
		{"a", "a", false, false},
		{"a", "A", false, false},
		{"a", "b", true, false},
		{"zzzzzZ", "A", false, true},
		{"POWERDNS", "powerdns", false, false},
		{"POWER", "power1", true, false},
		{"", "", false, false},
		{"nl", "com", false, true},
	}

	for _, r := range (tests1) {
		a := NewDNSLabel(r.a)
		b := NewDNSLabel(r.b);
		r1 := a.Less(b)
		r2 := b.Less(a)

		if r1 != r.x || r2 != r.y {
			t.Errorf("a: %s, b: %s got (%v %v) expected (%v %v)", a, b, r1, r2, r.x, r.y)
		}
	}

	tests2 := []struct {
		a, b string
	}{
		{"Donald E. Eastlake 3rd", "Donald\\032E\\.\\032Eastlake\\0323rd"},
	}
	for _, r := range (tests2) {
		a := NewDNSLabel(r.a)
		b := a.String()
		if b != r.b {
			t.Errorf("a: %s got \n'%v' expected \n'%v'", a, b, r.b)
		}
	}
}

func TestDNSName(t *testing.T) {
	tests1 := []struct {
		name *Name
		str  string
	}{
		{NewDNSName([]string{}), "."},
		{NewDNSName([]string{"www", "powerdns", "com"}), "www.powerdns.com."},
		{NewDNSName([]string{"powerdns", "com."}), "powerdns.com\\.."},
		{NewDNSName([]string{"p\x00werdns", "com"}), "p\\000werdns.com."},
	}

	for _, x := range (tests1) {
		n := x.name
		s := n.String()
		if s != x.str {
			t.Errorf("%s: got %v, expected %v", n, s, x.str)
		}
	}

	tests2 := []struct {
		a, b *Name
		x, y bool
	}{
		{NewDNSName([]string{}), NewDNSName([]string{}), false, false},
		{NewDNSName([]string{"aap", "nl"}), NewDNSName([]string{"aap", "com"}), false, true},
		{NewDNSName([]string{"AAP", "NL"}), NewDNSName([]string{"Aap", "nl"}), false, false},
		{NewDNSName([]string{"nl"}), NewDNSName([]string{"0", "nl"}), false, true},
		{NewDNSName([]string{"0", "nl"}), NewDNSName([]string{"0", "nl", "com"}), true, false},
	}

	for _, tt := range (tests2) {
		r1 := tt.a.Less(tt.b)
		r2 := tt.b.Less(tt.a)

		if r1 != tt.x || r2 != tt.y {
			t.Errorf("a: %s, b: %s got (%v %v) expected (%v %v)", tt.a, tt.b, r1, r2, tt.x, tt.y)
		}
	}

}

func TestMakeDNSName(t *testing.T) {
	tests1 := []struct {
		name *Name
		str  string
	}{
		{MakeDNSName(""), "."},
		{MakeDNSName("."), "."},
		{MakeDNSName("aa.bb.cc"), "aa.bb.cc."},
		{MakeDNSName("aa..bb.cc"), "aa.bb.cc."}, // XXX correct?
	}

	for _, x := range (tests1) {
		n := x.name
		s := n.String()
		if s != x.str {
			t.Errorf("%s: got %v, expected %v", n, s, x.str)
		}
	}
}
