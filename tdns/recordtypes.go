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
	ToMessage(w *MessageWriter) []byte
	String() string
}

type UnknownGen struct {
	Data []byte
}

func (a *UnknownGen) Gen(r *MessageReader, l uint16) {
	a.Data = r.getBlob(l, nil)
}

func (a *UnknownGen) ToMessage(*MessageWriter) []byte {
	return a.Data
}

func (a *UnknownGen) String() string {
	return fmt.Sprintf("%x", a.Data)
}

type AGen struct {
	IP net.IP
}

func (a *AGen) Gen(r *MessageReader, l uint16) {
	data := r.getUint32(nil)
	a.IP = []byte{byte(data >> 24), byte(data >> 16), byte(data >> 8), byte(data)}
}

func (a *AGen) ToMessage(*MessageWriter) []byte {
	return a.IP
}

func (a *AGen) String() string {
	return a.IP.String()
}

type AAAAGen struct {
	IP net.IP
}

func (a *AAAAGen) Gen(r *MessageReader, l uint16) {
	a.IP = r.getBlob(16, nil)
}

func (a *AAAAGen) ToMessage(*MessageWriter) []byte {
	return a.IP
}

func (a *AAAAGen) String() string {
	return a.IP.String()
}

type NSGen struct {
	NSName *Name
}

func (a *NSGen) Gen(r *MessageReader, l uint16) {
	a.NSName = r.getName(nil)
}

func (a *NSGen) ToMessage(w *MessageWriter) []byte {
	var buf bytes.Buffer
	w.XfrName(&buf, a.NSName, true)
	return buf.Bytes()
}

func (a *NSGen) String() string {
	return a.NSName.String()
}

type CNAMEGen struct {
	CName *Name
}

func (a *CNAMEGen) Gen(r *MessageReader, l uint16) {
	a.CName = r.getName(nil)
}

func (a *CNAMEGen) ToMessage(w *MessageWriter) []byte {
	var buf bytes.Buffer
	w.XfrName(&buf, a.CName, true)
	return buf.Bytes()
}

func (a *CNAMEGen) String() string {
	return a.CName.String()
}

type SOAGen struct {
	MName, RName *Name
	Serial, Refresh, Retry, Expire, Minimum uint32
}

func (s *SOAGen) Gen(r *MessageReader, l uint16) {
	s.MName = r.getName(nil)
	s.RName = r.getName(nil)
	s.Serial = r.getUint32(nil)
	s.Refresh = r.getUint32(nil)
	s.Retry = r.getUint32(nil)
	s.Expire = r.getUint32(nil)
	s.Minimum = r.getUint32(nil)

}

func (s *SOAGen) ToMessage(w *MessageWriter) []byte {
	var buf bytes.Buffer
	w.XfrName(&buf, s.MName, true)
	w.XfrName(&buf, s.RName, true)
	XfrUInt32(&buf, s.Serial)
	XfrUInt32(&buf, s.Refresh)
	XfrUInt32(&buf, s.Retry)
	XfrUInt32(&buf, s.Expire)
	XfrUInt32(&buf, s.Minimum)
	return buf.Bytes()
}

func (s *SOAGen) String() string {
	return fmt.Sprintf("%s %s %d %d %d %d %d", s.MName, s.RName, s.Serial, s.Refresh, s.Retry, s.Expire, s.Minimum)
}

type MXGen struct {
	Prio uint16
	Name *Name
}

func (m *MXGen) Gen(r *MessageReader, l uint16) {
	m.Prio = r.getUint16(nil)
	m.Name = r.getName(nil)
}

func (m *MXGen) ToMessage(w *MessageWriter) []byte {
	var buf bytes.Buffer
	XfrUInt16(&buf, m.Prio)
	w.XfrName(&buf, m.Name, true)
	return buf.Bytes()
}

func (m *MXGen) String() string {
	return fmt.Sprintf("%d %s", m.Prio, m.Name)
}