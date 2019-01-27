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
	"fmt"
	"net"
)

type RRGen interface {
	Gen(r *MessageReader, l uint16)
	ToMessage() []byte
	String() string
}

type UnknownGen struct {
	Data []byte
}

func (a *UnknownGen) Gen(r * MessageReader, l uint16) {
	a.Data = r.getBlob(l,nil)
}

func (a *UnknownGen) ToMessage() []byte {
	return a.Data
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

func (a *AGen) ToMessage() []byte {
	return a.IP
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

func (a *AAAAGen) ToMessage() []byte {
	return a.IP
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

func (a *NSGen) ToMessage() []byte {
	var buf bytes.Buffer
	XfrName(&buf, a.NSName, true)
	return buf.Bytes()
}

func (a *NSGen) String() string {
	return a.NSName.String()
}

type CNAMEGen struct {
	CName *Name
}

func (a *CNAMEGen) Gen(r * MessageReader, l uint16) {
	a.CName = r.getName(nil)
}

func (a *CNAMEGen) ToMessage() []byte {
	var buf bytes.Buffer
	XfrName(&buf, a.CName, true)
	return buf.Bytes()
}

func (a *CNAMEGen) String() string {
	return a.CName.String()
}
