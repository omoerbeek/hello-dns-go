package tdns

import (
	"encoding/base64"
	"net"
	"testing"
)

/* RFC 5702
6.1.  RSA/SHA-256 Key and Signature

   Given a private key with the following values (in Base64):

   Private-key-format: v1.2
   Algorithm:       8 (RSASHA256)
   Modulus:         wVwaxrHF2CK64aYKRUibLiH30KpPuPBjel7E8ZydQW1HYWHfoGm
                    idzC2RnhwCC293hCzw+TFR2nqn8OVSY5t2Q==
   PublicExponent:  AQAB
   PrivateExponent: UR44xX6zB3eaeyvTRzmskHADrPCmPWnr8dxsNwiDGHzrMKLN+i/
                    HAam+97HxIKVWNDH2ba9Mf1SA8xu9dcHZAQ==
   Prime1:          4c8IvFu1AVXGWeFLLFh5vs7fbdzdC6U82fduE6KkSWk=
   Prime2:          2zZpBE8ZXVnL74QjG4zINlDfH+EOEtjJJ3RtaYDugvE=
   Exponent1:       G2xAPFfK0KGxGANDVNxd1K1c9wOmmJ51mGbzKFFNMFk=
   Exponent2:       GYxP1Pa7CAwtHm8SAGX594qZVofOMhgd6YFCNyeVpKE=
   Coefficient:     icQdNRjlZGPmuJm2TIadubcO8X7V4y07aVhX464tx8Q=

   The DNSKEY record for this key would be:

   example.net.     3600  IN  DNSKEY  (256 3 8 AwEAAcFcGsaxxdgiuuGmCkVI
                    my4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8P
                    kxUdp6p/DlUmObdk= );{id = 9033 (zsk), size = 512b}

   With this key, sign the following RRSet, consisting of 1 A record:

   www.example.net. 3600  IN  A  192.0.2.91

   If the inception date is set at 00:00 hours on January 1st, 2000, and
   the expiration date at 00:00 hours on January 1st, 2030, the
   following signature should be created:

 www.example.net. 3600  IN  RRSIG  (A 8 3 3600 20300101000000
                     20000101000000 9033 example.net. kRCOH6u7l0QGy9qpC9
                     l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEa
                     cFYK/lPtPiVYP4bwg==);{id = 9033}
*/

func TestValidateRSA256(t *testing.T) {
	pubkeydata, _ := base64.StdEncoding.DecodeString("AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk=")
	dnskey := DNSKEYGen{Flags: 256, Protocol:3, Algorithm:RSASHA256, PubKey:pubkeydata}
	//dnskeyRR := RRec{Name: *MakeName("example.net"), Type:DNSKEY, Class:IN, TTL:3600, Data:&dnskey}

	if dnskey.KeyTag() != 9033 {
		t.Error("Keytag mismatch")
	}

	a := AGen{IP: net.ParseIP("192.0.2.91").To4()}
	aRR := RRec{Name: *MakeName("www.example.net"), Type:A, Class:IN, TTL:3600, Data:&a}

	s, _ := base64.StdEncoding.DecodeString("kRCOH6u7l0QGy9qpC9l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEacFYK/lPtPiVYP4bwg==")
	x := TimeFromHumanReadbale("20300101000000")
	y := TimeFromHumanReadbale("20000101000000")

	rrsig := RRSIGGen{Type: A, Algorithm: RSASHA256, Labels: 3, TTL: 3600, Expiration: x, Inception: y,
		KeyTag: 9033, Signer: MakeName("example.net"), Signature: s}
	rrsigRR := RRec{Name: *MakeName("www.example.net"), Type:RRSIG, Class:IN, TTL:3600, Data:&rrsig}

	if err := ValidateSignature([]*RRec{&aRR }, &dnskey, &rrsigRR); err != nil {
		t.Error(err)
	}

}

/*
6.2.  RSA/SHA-512 Key and Signature

   Given a private key with the following values (in Base64):

   Private-key-format: v1.2
   Algorithm:       10 (RSASHA512)
   Modulus:         0eg1M5b563zoq4k5ZEOnWmd2/BvpjzedJVdfIsDcMuuhE5SQ3pf
                    Q7qmdaeMlC6Nf8DKGoUPGPXe06cP27/WRODtxXquSUytkO0kJDk
                    8KX8PtA0+yBWwy7UnZDyCkynO00Uuk8HPVtZeMO1pHtlAGVnc8V
                    jXZlNKdyit99waaE4s=
   PublicExponent:  AQAB
   PrivateExponent: rFS1IPbJllFFgFc33B5DDlC1egO8e81P4fFadODbp56V7sphKa6
                    AZQCx8NYAew6VXFFPAKTw41QdHnK5kIYOwxvfFDjDcUGza88qbj
                    yrDPSJenkeZbISMUSSqy7AMFzEolkk6WSn6k3thUVRgSlqDoOV3
                    SEIAsrB043XzGrKIVE=
   Prime1:          8mbtsu9Tl9v7tKSHdCIeprLIQXQLzxlSZun5T1n/OjvXSUtvD7x
                    nZJ+LHqaBj1dIgMbCq2U8O04QVcK3TS9GiQ==
   Prime2:          3a6gkfs74d0Jb7yL4j4adAif4fcp7ZrGt7G5NRVDDY/Mv4TERAK
                    Ma0TKN3okKE0A7X+Rv2K84mhT4QLDlllEcw==
   Exponent1:       v3D5A9uuCn5rgVR7wgV8ba0/KSpsdSiLgsoA42GxiB1gvvs7gJM
                    MmVTDu/ZG1p1ZnpLbhh/S/Qd/MSwyNlxC+Q==
   Exponent2:       m+ezf9dsDvYQK+gzjOLWYeKq5xWYBEYFGa3BLocMiF4oxkzOZ3J
                    PZSWU/h1Fjp5RV7aPP0Vmx+hNjYMPIQ8Y5w==
   Coefficient:     Je5YhYpUron/WdOXjxNAxDubAp3i5X7UOUfhJcyIggqwY86IE0Q
                    /Bk0Dw4SC9zxnsimmdBXW2Izd8Lwuk8FQcQ==

   The DNSKEY record for this key would be:

   example.net.    3600  IN  DNSKEY  (256 3 10 AwEAAdHoNTOW+et86KuJOWRD
                   p1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFD
                   xj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8g
                   pMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL
                   );{id = 3740 (zsk), size = 1024b}

   With this key, sign the following RRSet, consisting of 1 A record:

   www.example.net. 3600  IN  A  192.0.2.91

   If the inception date is set at 00:00 hours on January 1st, 2000, and
   the expiration date at 00:00 hours on January 1st, 2030, the
   following signature should be created:

   www.example.net. 3600  IN  RRSIG  (A 10 3 3600 20300101000000
                    20000101000000 3740 example.net. tsb4wnjRUDnB1BUi+t
                    6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRa
                    eUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOL
                    DiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw
                    =);{id = 3740}

 */

func TestValidateRSA512(t *testing.T) {
	pubkeydata, _ := base64.StdEncoding.DecodeString("AwEAAdHoNTOW+et86KuJOWRDp1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFDxj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8gpMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL")
	dnskey := DNSKEYGen{Flags: 256, Protocol:3, Algorithm:RSASHA512, PubKey:pubkeydata}
	//dnskeyRR := RRec{Name: *MakeName("example.net"), Type:DNSKEY, Class:IN, TTL:3600, Data:&dnskey}


	if dnskey.KeyTag() != 3740 {
		t.Error("Keytag mismatch")
	}

	a := AGen{IP: net.ParseIP("192.0.2.91").To4()}
	aRR := RRec{Name: *MakeName("www.example.net"), Type:A, Class:IN, TTL:3600, Data:&a}

	s, _ := base64.StdEncoding.DecodeString("tsb4wnjRUDnB1BUi+t6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRaeUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOLDiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw=")
	x := TimeFromHumanReadbale("20300101000000")
	y := TimeFromHumanReadbale("20000101000000")

	rrsig := RRSIGGen{Type: A, Algorithm: RSASHA512, Labels: 3, TTL: 3600, Expiration: x, Inception: y,
		KeyTag: 3740, Signer: MakeName("example.net"), Signature: s}
	rrsigRR := RRec{Name: *MakeName("www.example.net"), Type:RRSIG, Class:IN, TTL:3600, Data:&rrsig}

	if err := ValidateSignature([]*RRec{&aRR }, &dnskey, &rrsigRR); err != nil {
		t.Error(err)
	}

}