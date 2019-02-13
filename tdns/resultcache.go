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
	"math/rand"
	"net"
	"sync"
	"time"
)

const (
	DefaultNegCacheSeconds = 5 * 60
)

type (
	resulttype struct {
		resolveResult  *ResolveResult
		err            error
		timestamp, ttd time.Time
	}
	ResultCache struct {
		mutex            sync.Mutex
		NegCacheDuration time.Duration
		results          map[string]resulttype
	}
)

func computeTTL(now, inserttime time.Time, recordttl uint32) uint32 {
	passed := now.Sub(inserttime)
	ttl := time.Duration(recordttl) * time.Second
	//fmt.Printf("now=%v inserttime=%v recordttl=%v passed=%v d=%v ret=%v\n", now, inserttime, recordttl, passed, ttl, (ttl-passed).Seconds())
	if passed >= ttl {
		return 0
	} else {
		return uint32((ttl - passed).Seconds())
	}
}

func NewResultCache() *ResultCache {
	return &ResultCache{results: make(map[string]resulttype), NegCacheDuration: DefaultNegCacheSeconds * time.Second}
}

func (rc *ResultCache) Size() int {
	return len(rc.results)
}

func (rc *ResultCache) String() string {
	var buf bytes.Buffer
	for n, v := range rc.results {
		buf.WriteString(v.err.Error())
		buf.WriteString(v.timestamp.String())
		buf.WriteString("TTD: " + v.ttd.String())
		buf.WriteString(n)
		buf.WriteString("\n")
	}
	return buf.String()
}

func getNonExpired(old []*RRec, now, timestamp time.Time) (ret []*RRec, exp bool) {
	exp = false
	for _, v := range old {
		newttl := computeTTL(now, timestamp, v.TTL)
		if newttl < 1 {
			exp = true
			continue
		}
		// Make a copy
		data := *v
		data.TTL = newttl
		ret = append(ret, &data)
	}
	return ret, exp
}

func (rc *ResultCache) Get(name *Name, dnstype Type) (*ResolveResult, error) {
	k := fmt.Sprintf("%s/%s", name.K(), dnstype.String())
	rc.mutex.Lock()
	results, ok := rc.results[k]
	rc.mutex.Unlock()

	if !ok {
		return nil, nil
	}

	now := time.Now()
	var ret ResolveResult

	var exp bool
	if ret.Auths, exp = getNonExpired(results.resolveResult.Auths, now, results.timestamp); exp {
		return nil, nil
	}
	if ret.Intermediates, exp = getNonExpired(results.resolveResult.Intermediates, now, results.timestamp); exp {
		return nil, nil
	}
	if ret.Answers, exp = getNonExpired(results.resolveResult.Answers, now, results.timestamp); exp {
		return nil, nil
	}

	return &ret, results.err
}

func (rc *ResultCache) Put(name *Name, dnstype Type, r *ResolveResult, err error) {
	t := time.Now()
	k := fmt.Sprintf("%s/%s", name.K(), dnstype.String())

	rc.mutex.Lock()
	rc.results[k] = resulttype{resolveResult: r, err: err, timestamp: t, ttd: t.Add(rc.NegCacheDuration)}
	rc.mutex.Unlock()
}

func (rc *ResultCache) Info() string {
	rc.mutex.Lock()
	lb := len(rc.results)
	rc.mutex.Unlock()
	return fmt.Sprintf("Number entries in ResultCache: %d", lb)
}

func (rc *ResultCache) cleanup() {
	now := time.Now()
	rc.mutex.Lock()

	for k, results := range rc.results {
		var exp1, exp2, exp3 bool
		results.resolveResult.Auths, exp1 = getNonExpired(results.resolveResult.Auths, now, results.timestamp)
		results.resolveResult.Intermediates, exp2 = getNonExpired(results.resolveResult.Intermediates, now, results.timestamp)
		results.resolveResult.Answers, exp3 = getNonExpired(results.resolveResult.Answers, now, results.timestamp)
		if exp1 || exp2 || exp3 {
			delete(rc.results, k)
		}
	}
	rc.mutex.Unlock()
}

// XXX revisit flushing policy...
func (rc *ResultCache) cleanupNeg() {
	now := time.Now()
	rc.mutex.Lock()
	outer:
	for k, results := range rc.results {
		if now.After(results.ttd) {
			delete(rc.results, k)
			continue
		}
		for _, v := range results.resolveResult.Auths {
			newttl := computeTTL(now, results.timestamp, v.TTL)
			if newttl < 1 {
				delete(rc.results, k)
				continue outer
			}
		}
		for _, v := range results.resolveResult.Intermediates {
			newttl := computeTTL(now, results.timestamp, v.TTL)
			if newttl < 1 {
				delete(rc.results, k)
				continue outer
			}
		}
		for _, v := range results.resolveResult.Answers {
			newttl := computeTTL(now, results.timestamp, v.TTL)
			if newttl < 1 {
				delete(rc.results, k)
				continue outer
			}
		}
	}
	rc.mutex.Unlock()
}

func (rc *ResultCache) Run() {
	period := 10 * time.Second
	tick := time.Tick(period)
	for {
		select {
		case <-tick:
			rc.cleanup()
		}
	}
}

func (rc *ResultCache) RunNeg() {
	period := 10 * time.Second
	if period > rc.NegCacheDuration {
		period = rc.NegCacheDuration / 2
	}
	tick := time.Tick(period)
	for {
		select {
		case <-tick:
			rc.cleanupNeg()
		}
	}
}

type (
	cacheEntry struct {
		rRec      *RRec
		timestamp time.Time
	}

	RRCache struct {
		mutex sync.Mutex
		rr    map[string]map[string]cacheEntry
	}

	NameIP struct {
		Name string
		IP   net.IP
	}
)

func (ce *cacheEntry) String() string {
	now := time.Now()
	ttl := computeTTL(now, ce.timestamp, ce.rRec.TTL)
	return fmt.Sprintf("%s %d", ce.rRec.String(), ttl)
}

func NewRRCache() *RRCache {
	return &RRCache{rr: make(map[string]map[string]cacheEntry)}
}

func (c *RRCache) Size() int {
	return len(c.rr)
}

func (c *RRCache) String() string {
	var buf bytes.Buffer
	for n, vv := range c.rr {
		buf.WriteString(n)
		buf.WriteString("\n")
		for _, v := range vv {
			buf.WriteString("\t")
			buf.WriteString(v.String())
			buf.WriteString("\n")
		}
	}
	return buf.String()
}

func (c *RRCache) Put(m MessageReaderInterface) {

	if _, ok := m.(*cacheReader); ok {
		// If it's already coming from the cache...
		return
	}

	t := time.Now()

	c.mutex.Lock()
	for rrec := m.GetRR(); rrec != nil; rrec = m.GetRR() {
		k1 := fmt.Sprintf("%s/%s", rrec.Name.K(), rrec.Type.String())
		k2 := rrec.String()
		if c.rr[k1] == nil {
			c.rr[k1] = make(map[string]cacheEntry)
		}
		c.rr[k1][k2] = cacheEntry{rrec, t}
	}
	c.mutex.Unlock()
	m.Reset()
}

func (c *RRCache) getByName(name *Name, dnstype Type) ([]RRec, bool) {
	k := fmt.Sprintf("%s/%s", name.K(), dnstype.String())
	c.mutex.Lock()
	rrset, ok := c.rr[k]
	c.mutex.Unlock()

	if !ok {
		return nil, false
	}

	var ret []RRec
	now := time.Now()
	for _, cachentry := range rrset {
		newttl := computeTTL(now, cachentry.timestamp, cachentry.rRec.TTL)
		if newttl < 1 {
			continue // or return empty set?
		}
		// Make a copy
		item := *cachentry.rRec
		item.TTL = newttl
		ret = append(ret, item)
	}
	if len(ret) == 0 {
		return nil, false
	}

	return ret, true
}

func (c *RRCache) get(name *Name, dnstype Type) ([]RRec, bool) {
	for e := name.Name.Front(); e != nil; e = e.Next() {
		tname := NewNameFromTail(e)
		set, ok := c.getByName(tname, dnstype)
		if !ok {
			continue
		} else {
			return set, true
		}
	}
	return nil, false
}

func (c *RRCache) GetNS(name *Name) []NameIP {
	set, ok := c.get(name, NS)
	if !ok {
		return nil
	}
	var ret []NameIP
	for _, s := range set {
		ns := s.Data.(*NSGen).NSName
		as, ok := c.get(ns, A)
		if ok {
			for _, a := range as {
				ret = append(ret, NameIP{s.Name.String(), a.Data.(*AGen).IP})
			}
		}
		aaaas, ok := c.get(ns, AAAA)
		if ok {
			for _, a := range aaaas {
				ret = append(ret, NameIP{s.Name.String(), a.Data.(*AAAAGen).IP})
			}
		}
	}
	rand.Shuffle(len(ret), func(i, j int) {
		ret[i], ret[j] = ret[j], ret[i]
	})

	return ret
}

type cacheReader struct {
	dh      Header
	name    *Name
	dnstype Type
	class   Class
	rr      []RRec
	pos		int
}

func (c *cacheReader) FromCache() bool {
	return true
}

func (c *cacheReader) DH() *Header {
	return &c.dh
}

func (c *cacheReader) Name() *Name {
	return c.name
}

func (c *cacheReader) Type() Type {
	return c.dnstype
}

func (c *cacheReader) Class() Class {
	return c.class
}

func (c *cacheReader) Reset() {
	c.pos = 0
}

func (c *RRCache) GetRRSet(name *Name, dnstype Type) MessageReaderInterface {
	m := cacheReader{name: name, dnstype: dnstype, class: IN}

	if rrset, ok := c.getByName(name, dnstype); ok {
		m.rr = rrset
		return &m
	}
	if rrset, ok := c.getByName(name, CNAME); ok {
		m.rr = rrset
		return &m
	}
	if rrset, ok := c.get(name, dnstype); ok {
		m.rr = rrset
		return &m
	}
	return nil
}

func (c *cacheReader) GetRR() (rrec *RRec) {
	if c.pos >= len(c.rr) {
		return nil
	}
	ret := &c.rr[c.pos]
	c.pos++
	return ret
}

func (c *RRCache) cleanup() {
	c.mutex.Lock()
	now := time.Now()
	for key, cachentries := range c.rr {
		for n, cachentry := range cachentries {
			//fmt.Println(cachentry.String())
			newttl := computeTTL(now, cachentry.timestamp, cachentry.rRec.TTL)
			if newttl < 1 {
				delete(cachentries, n)
			}
		}
		if len(cachentries) == 0 {
			delete(c.rr, key)
		}
	}
	c.mutex.Unlock()
}

func (c *RRCache) Run() {
	period := 60 * time.Second
	tick := time.Tick(period)
	for {
		select {
		case <-tick:
			c.cleanup()
		}
	}
}

func (c *RRCache) Info() string {
	c.mutex.Lock()
	lb := len(c.rr)
	c.mutex.Unlock()
	return fmt.Sprintf("Number entries in RRCache: %d", lb)
}
