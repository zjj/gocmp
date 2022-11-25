package cmp

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"log"
	"ra/libs/certutil"
	"testing"
)

func TestEncryptedValue(x *testing.T) {
	privPem := `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgnz/JvYwnJB8GcdG+9gt3NOGMTEdM
Ycej5H7n62JC3uigCgYIKoEcz1UBgi2hRANCAAQCodlaEhJnObioRe329q+XhCPNXw5LKv83ga5z
X5bRoCO8H1FyaIWgKDd/BdaZx+n54Q8VCKd4wLvqEC1kH94k
-----END PRIVATE KEY-----`

	priv, err := certutil.ReadPrivateKeyFromBytes([]byte(privPem))
	if err != nil {
		log.Fatal(err)
	}

	encValue, err := base64.StdEncoding.DecodeString("u6RyMkGLSLE38JVWeW8XOwmwagc+QAX+frsuzOOliYADT+48oe7xihb7XdAMdVzN6cIZwWRvRFmes/0LkU6xKdvkLvCHYgj7lPhtBJN4Rk87Vu3i9ne7L+X5Woh2rNbe+Elx+OG10ZbyKi8h9xdzZ6WR+0W0papZUMwXK8t4WhGak0twr4cNXgnU6sYWiLJrS4n2MlX9RI2ztEriYjhDVGOQUzOoQ3NTFkTV/6ymhqEbgltRfnAYNxtZH2JErVl8zchDXC2+arVYRhZesq/ZwQ==")
	if err != nil {
		log.Fatal(err)
	}

	encSymmkey, err := base64.StdEncoding.DecodeString("MHkCIBGYnQnQ3tfLCKjraUTaAqXYwEvhTVEeX4juJjIXLWQzAiEAzk/rLjZGAoWL85V7igAo+1+8atZvb+jGV6Ez4v/NVW4EICBBODHFhoKISId+ZuGb0YWTSty2wn3UvGB9YHId6MKyBBDk4De46NomHKI92Vic1qUo")
	if err != nil {
		log.Fatal(err)
	}

	parmaters, err := base64.StdEncoding.DecodeString("BBCOtB+LmpejCkzz94Gh5h+Q")
	if err != nil {
		log.Fatal(err)
	}

	ev := EncryptedValue{
		EncValue: asn1.BitString{
			Bytes: encValue,
		},
		EncSymmKey: asn1.BitString{
			Bytes: encSymmkey,
		},
		SymmAlg: pkix.AlgorithmIdentifier{
			Algorithm: []int{1},
			Parameters: asn1.RawValue{
				Bytes: parmaters,
			},
		},
	}

	a, err := ev.ParsePrivateKey(priv.(crypto.Decrypter))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(a))
	fmt.Println(base64.StdEncoding.EncodeToString(a))
}
