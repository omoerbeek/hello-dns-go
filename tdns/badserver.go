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
		Name	*Name
		Type	Type
		// skip Class
	}
	Status struct {
		Count int
		TTD   time.Time
	}
)

const (
	DefaultBadCacheSeconds = 5 * 60 // per RFC 2308
)

var (
	badmutex sync.Mutex
	badaddresses = make(map[string]Status)
	BadCacheDuration = DefaultBadCacheSeconds * time.Second
)

func (b *BadServer) String() string {
	tcpkey := 0
	if b.TCP  {
		tcpkey = 1
	}
	ednskey := 0
	if b.EDNS {
		ednskey = 1
	}

	namekey := ""
	if b.Name != nil {
		namekey = b.Name.String()
	}
	typekey := ""
	if b.Type != 0 {
		typekey = b.Type.String()
	}
	return fmt.Sprintf("%s/%d/%d/%s/%s", b.Address.String(), tcpkey, ednskey, namekey, typekey)
}


func (a *BadServer) Bad() {
	key := a.String()
	badmutex.Lock()
	item, ok := badaddresses[key]

	if (ok) {
		badaddresses[key] = Status{Count: item.Count + 1, TTD: time.Now().Add(BadCacheDuration)}
	} else {
		badaddresses[key] = Status{Count: 1, TTD: time.Now().Add(BadCacheDuration)}
	}
	badmutex.Unlock()
}

func (a *Status) IsBad() bool {
	return a.Count >= 3
}

func (a *BadServer) IsBad() bool {
	badmutex.Lock()
	item, ok := badaddresses[a.String()]
	badmutex.Unlock()

	if (ok) {
		return item.IsBad()
	} else {
		return false
	}
}

func cleanupBad() {
	now := time.Now()
	badmutex.Lock()
	for key, value := range badaddresses {
		if now.After(value.TTD) {
			delete(badaddresses, key)
		}
	}
	badmutex.Unlock()
}
func RunBadServers() {
	period := 10 * time.Second
	if period > BadCacheDuration {
		period = BadCacheDuration / 2
	}
	tick := time.Tick(period)
	for {
		select {
		case <-tick:
			cleanupBad()
		}
	}
}

func BadServersInfo() string {
	list := make([]string, 0)
	badmutex.Lock()
	for k, v := range badaddresses {
		if v.IsBad() {
			list = append(list, k)
		}
	}
	badmutex.Unlock()
	return fmt.Sprintf("Number of bad servers: %d/%d\n%v", len(badaddresses), len(list), list)
}