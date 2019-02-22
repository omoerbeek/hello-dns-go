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
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"math/big"
)

const (
	// https://www.iana.org/assignments/dnskey-flags/dnskey-flags.xhtml
	// Those bit are in network byte order, we define host by order
	ZONE   Flags = 1 << (15 - 7)
	REVOKE       = 1 << (15 - 8)
	SEP          = 1 << (15 - 15)

	RSASHA1	= 5
	RSASHA256 = 8
	RSASHA512 = 10
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


func ValidateDNSKeyWithDS(name *Name, dnskey *DNSKEYGen, dsrecords []*RRec) error {

	keyTag := dnskey.KeyTag()
	flags := dnskey.Flags

	if flags&REVOKE != 0 {
		return fmt.Errorf("dnskey revoked")
	}
	if flags&ZONE == 0 {
		return fmt.Errorf("dnskey not a zone key")
	}
	ok := false
	for _, rec := range dsrecords {
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
		if bytes.Compare(computed, ds.Digest) == 0 {
			ok = true
		} else {
			return fmt.Errorf("digest mismatch")
		}

	}
	if ok {
		return nil
	}
	if flags&SEP == 0 {
		// IF it is not a SEP, no DS validation is needed, but it *should* be signed by a ZSK...
		// Need to check against RFC!
		return fmt.Errorf("no matching digest for non-SEP key")
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

func ValidateRSA(rrset []*RRec, key *DNSKEYGen, rrsig *RRec) error {
	ee := big.NewInt(0)
	ee.SetBytes(key.PubKey[1:key.PubKey[0]+1]) // XXX Validation!
	e := int(ee.Int64())
	pubkeyData := key.PubKey[key.PubKey[0]+1:]
	mod := big.NewInt(0)
	mod = mod.SetBytes(pubkeyData)
	pubkey := rsa.PublicKey{ N : mod, E: e}
	buf := rrsig.Data.(*RRSIGGen).ToRDATA(rrset)

	var f hash.Hash
	var h crypto.Hash
	switch key.Algorithm {
	case RSASHA256:
		f = sha256.New()
		h = crypto.SHA256
	case RSASHA512:
		f = sha512.New()
		h = crypto.SHA512
	default:
		return fmt.Errorf("NYI")
	}

	f.Write(buf)
	sum := f.Sum(nil)
	return rsa.VerifyPKCS1v15(&pubkey, h, sum, rrsig.Data.(*RRSIGGen).Signature)
}