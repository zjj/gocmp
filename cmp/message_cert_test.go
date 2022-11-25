package cmp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"testing"

	"github.com/zjj/golibkit/certutil"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

func TestCertDelete(x *testing.T) {
	sanLst := []DN{
		{
			Code:  "dNSName",
			Value: []byte("baidu.com"),
		},
		{
			Code:  "dNSName",
			Value: []byte("360.cn"),
		},
		{
			Code:  "rfc822Name",
			Value: []byte("test@360.cn"),
		},
	}

	_ = sanLst
	extLst := []DN{
		{
			OID:   []int{1, 2, 840, 113549, 1, 9, 14},
			Value: []byte("xxxxxxxxx"),
		},
		{
			OID:      []int{1, 2, 840, 113549, 1, 9, 15},
			Critical: true,
			Value:    []byte("aaaaaaaaa"),
		},
	}
	_ = extLst

	pemx := `-----BEGIN CERTIFICATE REQUEST-----
MIICxjCCAa4CAQAwcDESMBAGA1UEAwwJ54ix5Y+R5ZGGMQswCQYDVQQKDAIzNDEL
MAkGA1UECwwCNDMxCzAJBgNVBAYTAkNOMQowCAYDVQQIDAE0MQswCQYDVQQHDAI0
NDEaMBgGCSqGSIb3DQEJARYLNDQzQGZkYS5jb20wggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQCmbtSuDRNt1zzlspGV/uIXAM6nOoNy9NV277hg8cDxbLU5
3HJdSTkQAQrRPuygJFvNQH3YXectY+pnVOS+7Z/xs5f01DiszXmq1/nLfAhaYgTb
BGzO0XNt3DWXbJ/kafLH05oRlSiuSuungMsc+xe6JqU8DIKGEb6uJqCrNJUYY7+u
dDmqUyH/an4Ylircl/dEzsxgCGyXQ8MxwTVn48WtHMRZp+9CdoCfazmxCmqfRvG2
KaOIT6bq3TQJnERh/77Tc2LB190DuLqIEoAY4A833xfwPOjquLkY29wstXEx1I4r
Ls8qR0MZIYuMvTPHTsqVm0QlqR/xiDUxCb3sLBeBAgMBAAGgETAPBgkqhkiG9w0B
CQ4xAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCJUSuD80EupymyqFb2RUyB6SVPojLm
MoTu7q9RBKqc0f34LeXJ5Fp6a9siD2oKCGQM4nYXKOfFnp+v0JZ9XJJGolJTQklj
QT03dNpAvEh1GyCiJmHY+x0kUvMegT9FFhFPNYFsCtJBivQefA2Wom6NelMgLt8f
kOTBrqwvGRgQlK02vJhz2X8zipJpQqE9nfwT+f/VDQgR02weEFurcabj4vzVwYDg
arjyiSQKpRT8o4aEzNTlsFB7Ji4q3D2txQT0CyBljSvfCDUTrIYZLxflZhN3HaQv
/w0s1MSXoIUSEaqTuF/spY3RMG0Vmu9tOzFM6RRqael/T4qYItH1bvFX
-----END CERTIFICATE REQUEST-----`

	block, _ := pem.Decode([]byte(pemx))
	der := block.Bytes
	/*
		b, err := certutil.GetRawPublicKeyInfoFromCSR(der)
		if err != nil {
			log.Fatal(err)
		}
	*/
	_ = der

	sn := new(big.Int).SetInt64(22)

	t := NewCertTemplate(sn)

	//now := time.Now().UTC()
	//t.SetVaidity(now, now.Add(time.Hour*time.Duration(24*365)))

	dnLst := []DN{
		{
			OID:   oidCountry,
			Value: []byte("china"),
		},
		{
			OID:   oidCommonName,
			Value: []byte("360.cn"),
		},
		{
			OID:   []int{1, 2, 840, 113549, 1, 1, 1},
			Value: []byte("www.360.cn"),
		},
	}
	_ = dnLst

	//subjectSeq := BuildSubject(dnLst)
	//ext, err := BuildExtensions(sanLst, extLst)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//t.SetSubject(subjectSeq)
	//t.SetExtension(ext)
	//t.SetPublicKeyWithCSR(der)

	b, err := asn1.Marshal(*t)

	if err != nil {
		fmt.Println("GGGGGG")
		log.Fatal(err)
	}
	fmt.Printf("b:%s", b)
	bb64 := base64.StdEncoding.EncodeToString(b)
	fmt.Println(bb64)

	//-----------------------------

	//rr :=RevDetails{
	//	CertDetails:     *t,
	//	RevocationReason:asn1.BitString{
	//		Bytes:     []byte{1},
	//		BitLength: 8,
	//	},
	//}
	//
	//msg := RevReqContent{
	//	rr,
	//}
	//
	//wrap := struct {
	//	RR interface{}
	//}{
	//	RR: msg,
	//}
	//
	//bytes, err := asn1.MarshalWithParams(wrap,"tag:11,explict")
	//if err != nil {
	//	log.Fatal(err)
	//}

	rr, err := NewPKIBodyRRasn1([]CertTemplate{*t})
	if err != nil {
		log.Fatal(err)
	}

	//---------

	//s := base64.StdEncoding.EncodeToString(rr)
	//fmt.Println(s)

	cert, _ := ioutil.ReadFile("/Users/wyh/go/src/ra/libs/certutil/cmp/certs/server.cert")

	block, _ = pem.Decode([]byte(cert))

	{
		//cr, err := NewPKIBodyCRasn1([]CertTemplate{*t, *t})
		//if err != nil {
		//	log.Fatal(err)
		//}
		header := NewPKIHeader()
		algo := pkix.AlgorithmIdentifier{
			Algorithm:  certutil.OIDSignatureSHA256WithRSA,
			Parameters: asn1.NullRawValue,
		}

		header.SetProtectionAlg(algo)

		msg := PKIMessage{}
		msg.Header = *header
		msg.SetBody(rr)
		certRaw := Certificate{
			Raw: block.Bytes,
		}
		msg.ExtraCerts = []Certificate{certRaw}

		b := []byte("asfasdfasfasfasfasfsafasf")
		msg.Protection = asn1.BitString{
			Bytes:     b,
			BitLength: len(b) * 8,
		}

		bytes, err := asn1.Marshal(msg)
		if err != nil {
			log.Fatal(err)
		}
		s := base64.StdEncoding.EncodeToString(bytes)
		fmt.Println("PKIMessage:", s)
		//panic(s)
		fmt.Println()

		toSignData := struct {
			Header interface{}
			Body   interface{}
		}{
			msg.Header,
			msg.Body,
		}

		{
			bytes, err := asn1.Marshal(toSignData)
			if err != nil {
				log.Fatal(err)
			}
			s := base64.StdEncoding.EncodeToString(bytes)
			fmt.Println(s)
			var (
				RaPriv         crypto.PrivateKey
				RaPrivHashAlgo x509.SignatureAlgorithm
				RaPrivAlgoOID  asn1.ObjectIdentifier
			)
			ServerPrivateKeyPath := "/Users/wyh/go/src/ra/libs/certutil/cmp/certs/private.key"
			RaPrivKey, err := ioutil.ReadFile(ServerPrivateKeyPath)
			if err != nil {
				log.Fatal(err)
			}
			RaPriv, _ = certutil.ReadPrivateKeyFromBytes(RaPrivKey)

			switch RaPriv.(type) {
			case *rsa.PrivateKey:
				RaPrivHashAlgo = x509.SHA256WithRSA
				RaPrivAlgoOID = certutil.OIDSignatureSHA256WithRSA
			case *ecdsa.PrivateKey:
				RaPrivHashAlgo = x509.ECDSAWithSHA256
				RaPrivAlgoOID = certutil.OIDSignatureECDSAWithSHA256
			case *sm2.PrivateKey:
				RaPrivHashAlgo = x509.SM2WithSM3
				RaPrivAlgoOID = certutil.OIDSignatureSM2WithSM3
			default:
				log.Fatal("no vaild privatekey found xxx")
			}
			_ = RaPrivAlgoOID
			_ = RaPrivHashAlgo
			err = msg.SignBy(RaPriv.(crypto.Signer))
			if err != nil {
				log.Fatal(err)
			}

			{
				bytes, err := asn1.Marshal(msg)
				if err != nil {
					log.Fatal(err)
				}
				s := base64.StdEncoding.EncodeToString(bytes)
				fmt.Println(s)
			}
		}
	}

}
