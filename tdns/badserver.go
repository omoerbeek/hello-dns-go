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
	"fmt"
	"net"
	"sync"
	"time"
)

type (
	BadServer struct {
		Address net.IP
		TCP     bool
		EDNS    bool
		Name    *Name
		Type    Type
		// skip Class
	}
	badstatus struct {
		Count int
		TTD   time.Time
	}

	BadServerCache struct {
		badmutex         sync.Mutex
		badaddresses     map[string]badstatus
		BadCacheDuration time.Duration
	}
)

const (
	DefaultBadCacheSeconds = 5 * 60 // per RFC 2308
)

func NewBadServerCache() BadServerCache {
	return BadServerCache{badaddresses: make(map[string]badstatus), BadCacheDuration: DefaultBadCacheSeconds * time.Second}
}

func (b *BadServer) String() string {
	tcpkey := "udp"
	if b.TCP {
		tcpkey = "tcp"
	}
	ednskey := ""
	if b.EDNS {
		ednskey = "edns"
	}

	namekey := ""
	if b.Name != nil {
		namekey = b.Name.String()
	}
	typekey := ""
	if b.Type != 0 {
		typekey = b.Type.String()
	}
	return fmt.Sprintf("%s/%s/%s/%s/%s", b.Address.String(), tcpkey, ednskey, namekey, typekey)
}

func (b *BadServerCache) Bad(a *BadServer) {
	key := a.String()
	b.badmutex.Lock()
	item, ok := b.badaddresses[key]

	if ok {
		b.badaddresses[key] = badstatus{Count: item.Count + 1, TTD: time.Now().Add(b.BadCacheDuration)}
	} else {
		b.badaddresses[key] = badstatus{Count: 1, TTD: time.Now().Add(b.BadCacheDuration)}
	}
	b.badmutex.Unlock()
}

func (a *badstatus) IsBad() bool {
	return a.Count >= 3
}

func (b *BadServerCache) IsBad(a *BadServer) bool {
	b.badmutex.Lock()
	item, ok := b.badaddresses[a.String()]
	b.badmutex.Unlock()

	if ok {
		return item.IsBad()
	} else {
		return false
	}
}

func (b *BadServerCache) cleanupBad() {
	now := time.Now()
	b.badmutex.Lock()
	for key, value := range b.badaddresses {
		if now.After(value.TTD) {
			delete(b.badaddresses, key)
		}
	}
	b.badmutex.Unlock()
}

func (b *BadServerCache) Run() {
	period := 10 * time.Second
	if period > b.BadCacheDuration {
		period = b.BadCacheDuration / 2
	}
	tick := time.Tick(period)
	for {
		select {
		case <-tick:
			b.cleanupBad()
		}
	}
}

func (b *BadServerCache) Info() string {
	var list []string
	b.badmutex.Lock()
	for k, v := range b.badaddresses {
		if v.IsBad() {
			list = append(list, k)
		}
	}
	lb := len(b.badaddresses)
	b.badmutex.Unlock()
	return fmt.Sprintf("Number of bad servers: %d/%d", len(list), lb)
}
