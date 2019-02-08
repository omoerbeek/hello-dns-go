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
	"net"
	"os"
	"testing"
	"time"
)

func TestBadServer (t *testing.T) {
	a := net.ParseIP("127.0.0.1")
	s := BadServer{Address: a, TCP:false, EDNS:false, Name:nil, Type:A }
	if bs.IsBad(&s) {
		t.Error("s is badaddresses")
	}
	bs.Bad(&s)
	if bs.IsBad(&s) {
		t.Error("s is badaddresses")
	}
	bs.Bad(&s)
	bs.Bad(&s)
	bs.Bad(&s)
	if !bs.IsBad(&s) {
		t.Errorf("s is not badaddresses %v", bs.badaddresses)
	}
	time.Sleep(2*bs.BadCacheDuration)
	if bs.IsBad(&s) {
		t.Errorf("s is bad after timeout %v", bs.badaddresses)
	}
}

var bs BadServerCache

func TestMain(m *testing.M) {
	bs = NewBadServerCache()
	bs.BadCacheDuration = 1 * time.Second
	go bs.Run()
	os.Exit(m.Run())
}