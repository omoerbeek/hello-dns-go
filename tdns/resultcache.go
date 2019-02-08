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

type (
	resulttype struct {
		resolveResult *ResolveResult
		timestamp time.Time
	}
	ResultCache struct {
		mutex sync.Mutex
		results     map[string]resulttype
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

func NewResultCache() ResultCache {
	return ResultCache{results: make(map[string]resulttype)}
}

func (r *ResultCache) Size() int {
	return len(r.results)
}

func (r *ResultCache) String() string {
	var buf bytes.Buffer
	for n,_ := range r.results {
		buf.WriteString(n)
		buf.WriteString("\n")
	}
	return buf.String()
}

func (c *ResultCache) Get(name *Name, dnstype Type) *ResolveResult {
	k := fmt.Sprintf("%s/%s", name.K(), dnstype.String())
	c.mutex.Lock()
	results, ok  := c.results[k]
	c.mutex.Unlock()

	if !ok {
		return nil
	}

	now := time.Now()
	var ret ResolveResult
	for _, v := range results.resolveResult.Intermediates {
		newttl := computeTTL(now, results.timestamp, v.TTL)
		if newttl < 1 {
			// One expired result, no good
			return nil
		}
		// Make a copy
		data := *v
		data.TTL = newttl
		ret.Intermediates = append(ret.Intermediates, &data)
	}
	for _, v := range results.resolveResult.Res {
		newttl := computeTTL(now, results.timestamp, v.TTL)
		if newttl < 1 {
			// One expired result, no good
			return nil
		}
		// Make a copy
		data := *v
		data.TTL = newttl
		ret.Res = append(ret.Res, &data)
	}
	return &ret
}

func (c *ResultCache) Put(name *Name, dnstype Type, r *ResolveResult) {
	t := time.Now()
	k := fmt.Sprintf("%s/%s", name.K(), dnstype.String())

	c.mutex.Lock()
	c.results[k] = resulttype{r, t};
	c.mutex.Unlock()
}

func (c *ResultCache) Info() string {
	c.mutex.Lock()
	lb := len(c.results)
	c.mutex.Unlock()
	return fmt.Sprintf("Number entries in ResultCache: %d", lb)
}

// We're aggressive. The moment one RR expired, we zap the complete resultset
// Ths is in line with the code in Get()
func (c *ResultCache) cleanup() {
	now := time.Now()
	c.mutex.Lock()
	for k, results := range c.results {
		for _, v := range results.resolveResult.Intermediates {
			newttl := computeTTL(now, results.timestamp, v.TTL)
			if newttl < 1 {
				delete(c.results, k)
				continue
			}
		}
		for _, v := range results.resolveResult.Res {
			newttl := computeTTL(now, results.timestamp, v.TTL)
			if newttl < 1 {
				delete(c.results, k)
				continue
			}
		}
	}
	c.mutex.Unlock()
}

func (c *ResultCache) Run() {
	period := 10 * time.Second
	tick := time.Tick(period)
	for {
		select {
		case <-tick:
			c.cleanup()
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
		rr map[string]map[int]cacheEntry
	}

	NameIP struct {
		Name string
		IP   net.IP
	}
)

func (ce *cacheEntry) String() string {
	return fmt.Sprintf("%s %v", ce.rRec.String(), ce.timestamp)
}

func NewRRCache() RRCache {
	return RRCache{rr: make(map[string]map[int]cacheEntry)}
}

func (r *RRCache) Size() int {
	return len(r.rr)
}

func (r *RRCache) String() string {
	var buf bytes.Buffer
	for n,_ := range r.rr {
		buf.WriteString(n)
		buf.WriteString("\n")
	}
	return buf.String()
}

func (c *RRCache) Put(r *RRec) {
	t := time.Now()
	k := fmt.Sprintf("%s/%s", r.Name.K(), r.Type.String())

	c.mutex.Lock()
	if c.rr[k] == nil {
		c.rr[k] = make(map[int]cacheEntry)
	}
	c.rr[k][len(c.rr[k])] = cacheEntry{r, t}
	c.mutex.Unlock()
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

	return ret, true
}

func (c *RRCache) Get(name *Name, dnstype Type) ([]RRec, bool) {
	for e := name.Name.Front(); e != nil; e = e.Next() {
		tname := NewNameFromTail(e);
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
	set, ok := c.Get(name, NS)
	if !ok {
		return nil
	}
	var ret []NameIP
	for _, s := range set {
		ns := s.Data.(*NSGen).NSName
		as, ok := c.Get(ns, A)
		if ok {
			for _, a := range as {
				ret = append(ret, NameIP{s.Name.String(), a.Data.(*AGen).IP})
			}
		}
		aaaas, ok := c.Get(ns, AAAA)
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

func (c *RRCache) cleanup() {
	c.mutex.Lock()
	now := time.Now()
	for key, cachentries := range c.rr {
		for i, cachentry := range cachentries {
			//fmt.Println(cachentry.String())
			newttl := computeTTL(now, cachentry.timestamp, cachentry.rRec.TTL)
			if newttl < 1 {
				delete(cachentries, i)
			}
		}
		if len(cachentries) == 0 {
			delete(c.rr, key)
		}
	}
	c.mutex.Unlock()
}

func (c *RRCache) Run() {
	period := 10 * time.Second
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

