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

import "testing"

func TestDNSLabel(t *testing.T) {
	l1 := NewLabel("aap")
	if l1 == nil {
		t.Errorf("Label is nil")
	}
	l2 := NewLabel("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;lkl;kaaaaaaaap")
	if l2 != nil {
		t.Error("Label is not nil")
	}
	if l2 != nil {
		t.Error("Label is not nil")
	}

	l3 := NewLabel("\000123")
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
		{"aap", "aap", false, false},
	}

	for _, r := range tests1 {
		a := NewLabel(r.a)
		b := NewLabel(r.b)
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
	for _, r := range tests2 {
		a := NewLabel(r.a)
		b := a.String()
		if b != r.b {
			t.Errorf("a: %s got \n'%v' expected \n'%v'", a, b, r.b)
		}
	}

	tests3 := []struct {
		a, b string
		r    bool
	}{
		{"aap", "aap", true},
	}
	for _, r := range tests3 {
		a := NewLabel(r.a)
		b := NewLabel(r.b)
		tt := a.Equals(b)
		if r.r != tt {
			t.Errorf("%s %s got %v expected %v", a, b, r, r.r)
		}
	}

}

func TestName(t *testing.T) {
	tests1 := []struct {
		name *Name
		str  string
	}{
		{NewName([]string{}), "."},
		{NewName([]string{"www", "powerdns", "com"}), "www.powerdns.com."},
		{NewName([]string{"powerdns", "com."}), "powerdns.com\\.."},
		{NewName([]string{"p\x00werdns", "com"}), "p\\000werdns.com."},
	}

	for _, x := range tests1 {
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
		{NewName([]string{}), NewName([]string{}), false, false},
		{NewName([]string{"aap", "nl"}), NewName([]string{"aap", "com"}), false, true},
		{NewName([]string{"AAP", "NL"}), NewName([]string{"Aap", "nl"}), false, false},
		{NewName([]string{"nl"}), NewName([]string{"0", "nl"}), false, true},
		{NewName([]string{"0", "nl"}), NewName([]string{"0", "nl", "com"}), true, false},
	}

	for _, tt := range tests2 {
		r1 := tt.a.Less(tt.b)
		r2 := tt.b.Less(tt.a)

		if r1 != tt.x || r2 != tt.y {
			t.Errorf("a: %s, b: %s got (%v %v) expected (%v %v)", tt.a, tt.b, r1, r2, tt.x, tt.y)
		}
	}

	tests3 := []struct {
		a, b *Name
		x    bool
	}{
		{NewName([]string{}), NewName([]string{}), true},
		{NewName([]string{"aap", "nl"}), NewName([]string{"aap", "com"}), false},
		{NewName([]string{"AAP", "NL"}), NewName([]string{"Aap", "nl"}), true},
		{NewName([]string{"nl"}), NewName([]string{"0", "nl"}), false},
		{NewName([]string{"0", "nl"}), NewName([]string{"nl"}), true},
		{NewName([]string{"ns", "aap", "nl"}), NewName([]string{"aap", "nl"}), true},
	}

	for _, tt := range tests3 {
		r1 := tt.a.IsPartOf(tt.b)

		if r1 != tt.x {
			t.Errorf("a: %s, b: %s got %v expected %v", tt.a, tt.b, r1, tt.x)
		}
	}

}

func TestMakeName(t *testing.T) {
	tests1 := []struct {
		name *Name
		str  string
	}{
		{MakeName(""), "."},
		{MakeName("."), "."},
		{MakeName("aa.bb.cc"), "aa.bb.cc."},
		{MakeName("aa..bb.cc"), "aa.bb.cc."}, // XXX correct?
	}

	for _, x := range tests1 {
		n := x.name
		s := n.String()
		if s != x.str {
			t.Errorf("%s: got %v, expected %v", n, s, x.str)
		}
	}
}
