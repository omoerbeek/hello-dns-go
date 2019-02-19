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
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
)

/*
<TrustAnchor id="380DC50D-484E-40D0-A3AE-68F2B18F61C7" source="http://data.iana.org/root-anchors/root-anchors.xml">
<Zone>.</Zone>
<KeyDigest id="Kjqmt7v" validFrom="2010-07-15T00:00:00+00:00" validUntil="2019-01-11T00:00:00+00:00">
<KeyTag>19036</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Digest>
49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5
</Digest>
</KeyDigest>
<KeyDigest id="Klajeyz" validFrom="2017-02-02T00:00:00+00:00">
<KeyTag>20326</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Digest>
E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
</Digest>
</KeyDigest>
</TrustAnchor>
*/

var TrustAnchor []*RRec

func init() {
	TrustAnchor = make([]*RRec, 2)
	d1, _ := hex.DecodeString("49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5")
	TrustAnchor[0] = &RRec{
		Section: Answer, Name: *MakeName(""), Type: DS, Class: IN,
		Data: &DSGen{KeyTag: 19036, Algorithm: 8, DigestType: 2, Digest: d1},
	}

	d2, _ := hex.DecodeString("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")
	TrustAnchor[1] = &RRec{
		Section: Answer, Name: *MakeName(""), Type: DS, Class: IN,
		Data: &DSGen{KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: d2},
	}
}

func Validate(m MessageReaderInterface, dsrecords []*RRec) error {
	// Group & sort etc
	// For now, only DS check for DNSKEY records
	var err error

	for rrec := m.GetRR(); rrec != nil; rrec = m.GetRR() {
		switch rrec.Type {
		case DNSKEY:
			err = ValidateDNSKey(&rrec.Name, rrec.Data.(*DNSKEYGen), dsrecords)
			fmt.Printf("%s %s ValidateDNSKey returned %v\n", rrec.Name.String(), rrec.Type, err)
		}

		if err != nil {
			break
		}
	}
	m.Reset()
	fmt.Printf("Validate returned %v\n", err)
	return err
}

func ValidateDNSKey(name *Name, dnskey *DNSKEYGen, dsrecords []*RRec) error {
	keyTag := dnskey.KeyTag()
	flags := dnskey.Flags
	fmt.Printf("Computed tag is %v, flags = %d\n", keyTag, flags)
	if flags&1 == 0 { // XXX check against RFC!
		return nil
	}
	if flags&128 != 0 {
		return nil // revoked
	}
	ok := false
	for _, rec := range dsrecords {
		fmt.Printf("REC is %v\n", rec)
		ds := rec.Data.(*DSGen)
		if ds == nil {
			panic("ds data is nil")
		}
		if ds.KeyTag != keyTag {
			continue
		}
		if ds.Algorithm != dnskey.Algorithm {
			continue
		}
		computed := dnskey.Digest(name, ds.DigestType)
		if computed == nil {
			fmt.Printf("UNKNOWN digest type %d\n", ds.DigestType)
			// XXX Check RFC what to do
			continue
		}
		fmt.Printf("%s DIGEST CHECK\ndnskey=%v\nds=%v\ncomputed=%s\n", name, dnskey, ds, base64.StdEncoding.EncodeToString(computed))
		if bytes.Compare(computed, ds.Digest) == 0 {
			fmt.Printf("%s DIGEST COMPARED OK\n", name)
			ok = true
		} else {
			return fmt.Errorf("digest mismatch")
		}

	}
	if ok {
		return nil
	}
	return fmt.Errorf("no matching digest found")
}

func (k *DNSKEYGen) Digest(name *Name, digesttype DigestType) []byte {
	var f hash.Hash = nil
	switch digesttype {
	case SHA1:
		f = sha1.New()
	case SHA256:
		f = sha256.New()
	case SHA384:
		f = sha512.New384()

		// XXX GHOST
	}
	var res []byte
	if f != nil {
		f.Write(name.Bytes())
		f.Write(k.ToMessage(nil))
		res = f.Sum(nil)
	}
	return res
}

// https://tools.ietf.org/html/rfc4034

//    /* Assumes that int is at least 16 bits.
//    * First octet of the key tag is the most significant 8 bits of the
//    * return value;
//    * Second octet of the key tag is the least significant 8 bits of the
//    * return value.
//    */
//
//unsigned int
//keytag (
//	unsigned char key[],  /* the RDATA part of the DNSKEY RR */
//	unsigned int keysize  /* the RDLENGTH */
//)
//{
//	unsigned long ac;     /* assumed to be 32 bits or larger */
//	int i;                /* loop index */
//
//	for ( ac = 0, i = 0; i < keysize; ++i )
//		ac += (i & 1) ? key[i] : key[i] << 8;
//	ac += (ac >> 16) & 0xFFFF;
//	return ac & 0xFFFF;
//}

func (k *DNSKEYGen) KeyTag() KeyTag {
	data := k.ToMessage(nil)
	var ac uint32
	for i, k := range data {
		if (i & 1) == 1 {
			ac += uint32(k)
		} else {
			ac += uint32(k) << 8
		}
	}
	ac += (ac >> 16) & 0xffff
	return KeyTag(ac)
}
