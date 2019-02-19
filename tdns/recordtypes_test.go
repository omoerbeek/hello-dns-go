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
	"encoding/base64"
	"encoding/hex"
	"testing"
)
// 02736500 0101 03 05

func TestDNSKeyDigest(t *testing.T) {
	name := MakeName("se.")
	pubkey, err := base64.StdEncoding.DecodeString(
		"AwEAAZYYG1hpk8XKHNHpdO/EEg+r4YmIEC4Fn3x2DEsygxDuoT9d/QCiX1pz0omFGCaVfCWHvaScVvWd4xP4kNDnSDQxBzPwLEXE3l0cLseMJ2YMQeBPf3hGhLs6VSDnGFKAzNG4fhri9EBTLv9ubL8Kx8cWQKuu3A5HRVD3li7lZB+0kmUKqGiIQdERKt/Ec36BkK93lyGags5RrR2VDdrXCj9Yay90KCKITk52AbwVoMPm0OYlPbD4ViBPMk5nmh/dPeCoZoVJxgANZ/doVQxR5vDkMBYxuhrXuQk3CvZBB011NsXxk9yHtHvp/5gjUVJjvhdRvjRB6/xYR03c9owi/aM=")
	if err != nil {
		t.Errorf("Decoding1")
	}
	dnskey := DNSKEYGen{Flags: 257, Protocol: 3, Algorithm: 5, PubKey: pubkey}

	digest := dnskey.Digest(name, SHA256)
	expected, err := hex.DecodeString("44388b3de9a22cafa8a12883f60a0f984472d0dfef0f63ed59a29be018658b28")
	if err != nil {
		t.Errorf("Decoding2")
	}

	if bytes.Compare(digest, expected) != 0 {
		t.Errorf("Got %X, expected %X", digest, expected)
	}
}

func TestDNSKeyDigestRoot(t *testing.T) {
	name := MakeName("")
	pubkey, err := base64.StdEncoding.DecodeString(
		"AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=")
	if err != nil {
		t.Errorf("Decoding1")
	}
	dnskey := DNSKEYGen{Flags: 257, Protocol: 3, Algorithm: 8, PubKey: pubkey}

	digest := dnskey.Digest(name, SHA256)
	expected := TrustAnchor[1].Data.(*DSGen).Digest

	if bytes.Compare(digest, expected) != 0 {
		t.Errorf("Got %X, expected %X", digest, expected)
	}
}