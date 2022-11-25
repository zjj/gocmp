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
	"time"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
	"github.com/zjj/golibkit/certutil"
)

/*
func TestNewPKIHeader(t *testing.T) {
	h := NewPKIHeaderWithAlgo([]int{1, 2, 3, 3, 4})
	bytes, _ := asn1.Marshal(*h)
	s := base64.StdEncoding.EncodeToString(bytes)
	fmt.Println(s)
}

func TestNewPKIMessage(t *testing.T) {
	msg := PKIMessage{}
	hPtr := NewPKIHeaderWithAlgo([]int{1, 2, 3, 3, 4})
	msg.Header = *hPtr

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
	fmt.Println(s)
}

func TestNewCertTmplate(x *testing.T) {
	t := NewCertTemplate(22)
	algo := newProtectionAlg([]int{1, 2, 156, 10197, 1, 501})
	t.SetSigningAlg(algo)

	now := time.Now().UTC()
	t.SetVaidity(now, now.Add(time.Hour*time.Duration(24*365)))
	subject := []pkix.AttributeTypeAndValue{
		{
			Type:  []int{2, 5, 4, 6},
			Value: "CN",
		},
		{
			Type:  []int{2, 5, 4, 5},
			Value: "CNxxxx",
		},
	}
	t.SetSubject(pkix.RDNSequence{subject})

	bytes, err := asn1.Marshal(*t)
	if err != nil {
		log.Fatal(err)
	}
	s := base64.StdEncoding.EncodeToString(bytes)
	fmt.Println(s)

}

func TestCertRequest(x *testing.T) {
	t := NewCertTemplate(22)
	algo := newProtectionAlg([]int{1, 2, 156, 10197, 1, 501})
	t.SetSigningAlg(algo)

	now := time.Now().UTC()
	t.SetVaidity(now, now.Add(time.Hour*time.Duration(24*365)))
	subject := []pkix.AttributeTypeAndValue{
		{
			Type:  []int{2, 5, 4, 6},
			Value: "CN",
		},
		{
			Type:  []int{2, 5, 4, 5},
			Value: "CNxxxx",
		},
	}
	t.SetSubject(pkix.RDNSequence{subject})

	cr := CertRequest{
		CertReqID:    1,
		CertTemplate: *t,
	}

	bytes, err := asn1.Marshal(cr)
	if err != nil {
		log.Fatal(err)
	}
	s := base64.StdEncoding.EncodeToString(bytes)
	fmt.Println(s)
}

func TestCertReqMsg(x *testing.T) {
	t := NewCertTemplate(22)
	algo := newProtectionAlg([]int{1, 2, 156, 10197, 1, 501})
	t.SetSigningAlg(algo)

	now := time.Now().UTC()
	t.SetVaidity(now, now.Add(time.Hour*time.Duration(24*365)))
	subject := []pkix.AttributeTypeAndValue{
		{
			Type:  []int{2, 5, 4, 6},
			Value: "CN",
		},
		{
			Type:  []int{2, 5, 4, 5},
			Value: "CNxxxx",
		},
	}
	t.SetSubject(pkix.RDNSequence{subject})

	cr := CertRequest{
		CertReqID:    1,
		CertTemplate: *t,
	}

	msg := CertReqMessage{
		CertReq: cr,
	}

	bytes, err := asn1.Marshal(msg)
	if err != nil {
		log.Fatal(err)
	}
	s := base64.StdEncoding.EncodeToString(bytes)
	fmt.Println(s)

	pkiBody := PKIBody{
		CR: []CertReqMessage{msg, msg},
	}
	{
		msg := PKIMessage{}
		hPtr := NewPKIHeaderWithAlgo([]int{1, 2, 3, 3, 4})
		msg.Header = *hPtr
		msg.Body = pkiBody

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
		fmt.Println(s)
	}

}
*/

func TestBuildExtensions(x *testing.T) {
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

	id := big.NewInt(int64(22))
	t := NewCertTemplate(id)

	now := time.Now().UTC()
	t.SetVaidity(now, now.Add(time.Hour*time.Duration(24*365)))

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

	subjectSeq := BuildSubject(dnLst)
	ext, err := BuildExtensions(sanLst, extLst)
	if err != nil {
		log.Fatal(err)
	}
	t.SetSubject(subjectSeq)
	t.SetExtension(ext)
	t.SetPublicKeyWithCSR(der)

	_, err = asn1.Marshal(*t)
	if err != nil {
		fmt.Println("GGGGGG")
		log.Fatal(err)
	}

	cr := CertRequest{
		CertReqID:    1,
		CertTemplate: *t,
	}

	msg := CertReqMessage{
		CertReq: cr,
	}

	bytes, err := asn1.Marshal(msg)
	if err != nil {
		log.Fatal(err)
	}

	s := base64.StdEncoding.EncodeToString(bytes)
	fmt.Println(s)

	cert, _ := ioutil.ReadFile("/home/pi/ra/certs/server.cert")

	block, _ = pem.Decode([]byte(cert))

	{
		cr, err := NewPKIBodyCRasn1([]CertTemplate{*t, *t})
		if err != nil {
			log.Fatal(err)
		}
		header := NewPKIHeader()
		algo := pkix.AlgorithmIdentifier{
			Algorithm:  certutil.OIDSignatureSHA256WithRSA,
			Parameters: asn1.NullRawValue,
		}

		header.SetProtectionAlg(algo)

		msg := PKIMessage{}
		msg.Header = *header
		msg.SetBody(cr)
		certRaw := Certificate{
			Raw: block.Bytes,
		}
		msg.ExtraCerts = []Certificate{certRaw, certRaw}

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
		fmt.Println(s)
		panic("")
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
			ServerPrivateKeyPath := "/home/pi/ra/certs/private.key"
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
				fmt.Println("xxxxx")
				fmt.Println(s)

			}
		}
	}

}

func TestBuildSubject(x *testing.T) {
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
	seq := BuildSubject(dnLst)

	bytes, err := asn1.Marshal(seq)
	if err != nil {
		log.Fatal(err)
	}
	s := base64.StdEncoding.EncodeToString(bytes)
	fmt.Println(s)

}

func TestPKIMessageCP(x *testing.T) {
	b64 := "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"
	asn1Body, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		log.Fatal(err)
	}

	cp := pkiMessageCP{}
	_, err = asn1.Unmarshal(asn1Body, &cp)
	if err != nil {
		log.Fatal(err)
	}

	/*
		{
			fmt.Println(len(cp.Header.Bytes))
			h := PKIHeader{}
			_, err := asn1.Unmarshal(cp.Header.FullBytes, &h)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(string(h.TransactionID))
		}

		{
			fmt.Println(len(cp.Body.Bytes))
			b := certRepMessage{}
			_, err := asn1.Unmarshal(cp.Body.Bytes, &b)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("capubs", len(b.CAPubs.Bytes))
			fmt.Println(base64.StdEncoding.EncodeToString(b.CAPubs.FullBytes))
			{
				capubs := certificate{}
				_, err := asn1.Unmarshal(b.CAPubs.Bytes, &capubs)
				if err != nil {
					log.Fatal(err)
				}
				//fmt.Println("len(capubs)", len(capubs))
			}

			fmt.Println(len(b.Responses.Bytes))
		}
	*/

	fmt.Println("protection", len(cp.Protection.Bytes))
	fmt.Println("protection", cp.Protection.BitLength)
	//fmt.Println(base64.StdEncoding.EncodeToString(cp.Body.Responses.FullBytes))
	fmt.Println(len(cp.ExtraCerts))
	fmt.Println(cp.ExtraCerts[0].TBSCertificate.SerialNumber)

	fmt.Println(len(cp.Body.Responses[0].Raw))
	fmt.Println(cp.Body.Responses[0].Status.Status)
	fmt.Println(cp.Body.Responses[0].Status.FailInfo)
	//fmt.Println(cp.Body.Responses[0].CertifiedKeyPair.FullBytes)
	//fmt.Println(len(cp.Body.Responses[0].CertifiedKeyPair.FullBytes))
	fmt.Println(len(cp.Body.Responses[0].CertifiedKeyPair.Raw))
	//fmt.Println(cp.Body.Responses[0].CertifiedKeyPair.Cert.TBSCertificate.SerialNumber)
	//fmt.Println(cp.Body.Responses[0].CertifiedKeyPair.PrivateKey.Bytes)
}

func TestPKIMessageCPSm2(x *testing.T) {
	b64 := "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"
	fmt.Println(b64)
	asn1Body, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		log.Fatal(err)
	}

	cp := pkiMessageCP{}
	_, err = asn1.Unmarshal(asn1Body, &cp)
	if err != nil {
		log.Fatal(err)
	}

	/*
		{
			fmt.Println(len(cp.Header.Bytes))
			h := PKIHeader{}
			_, err := asn1.Unmarshal(cp.Header.FullBytes, &h)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(string(h.TransactionID))
		}

		{
			fmt.Println(len(cp.Body.Bytes))
			b := certRepMessage{}
			_, err := asn1.Unmarshal(cp.Body.Bytes, &b)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("capubs", len(b.CAPubs.Bytes))
			fmt.Println(base64.StdEncoding.EncodeToString(b.CAPubs.FullBytes))
			{
				capubs := certificate{}
				_, err := asn1.Unmarshal(b.CAPubs.Bytes, &capubs)
				if err != nil {
					log.Fatal(err)
				}
				//fmt.Println("len(capubs)", len(capubs))
			}

			fmt.Println(len(b.Responses.Bytes))
		}
	*/

	fmt.Println("protection", len(cp.Protection.Bytes))
	fmt.Println("protection", cp.Protection.BitLength)
	//fmt.Println(base64.StdEncoding.EncodeToString(cp.Body.Responses.FullBytes))
	fmt.Println(len(cp.ExtraCerts))
	fmt.Println(cp.ExtraCerts[0].TBSCertificate.SerialNumber)

	fmt.Println(len(cp.Body.Responses[0].Raw))
	fmt.Println("ResponsesLength", len(cp.Body.Responses))
	fmt.Println(cp.Body.Responses[0].CertReqID)
	fmt.Println(cp.Body.Responses[1].CertReqID)
	fmt.Println("StatusRaw Length,", len(cp.Body.Responses[0].Status.Raw))
	fmt.Println("FailINfo", cp.Body.Responses[0].Status.FailInfo)
	//fmt.Println(cp.Body.Responses[0].CertifiedKeyPair.FullBytes)
	//fmt.Println(len(cp.Body.Responses[0].CertifiedKeyPair.FullBytes))
	fmt.Println(len(cp.Body.Responses[0].CertifiedKeyPair.Raw))
	//fmt.Println(cp.Body.Responses[0].CertifiedKeyPair.Cert.TBSCertificate.SerialNumber)
	//fmt.Println(cp.Body.Responses[0].CertifiedKeyPair.PrivateKey.Bytes)
	fmt.Println(cp.Body.Responses[0].CertifiedKeyPair.Raw)
	fmt.Println("CertifiedKeyPair Raw,", len(cp.Body.Responses[0].CertifiedKeyPair.Raw))
	fmt.Println(len(cp.Body.Responses[0].CertifiedKeyPair.CertOrEncCert.Cert.Raw))
	fmt.Println("XXXXX")
	fmt.Println(len(cp.Body.Responses[1].CertifiedKeyPair.CertOrEncCert.Cert.Raw))
	fmt.Println(cp.Body.Responses[1].CertifiedKeyPair.PrivateKey.KeyAlg.Algorithm.String())
	fmt.Printf("%b", cp.Body.Responses[1].CertifiedKeyPair.PrivateKey.EncSymmKey.Bytes)
	encValue := cp.Body.Responses[1].CertifiedKeyPair.PrivateKey.EncValue.Bytes
	fmt.Println(base64.StdEncoding.EncodeToString(encValue))

	//0000
	{
		fmt.Println("000000000 private")
		encValue := cp.Body.Responses[0].CertifiedKeyPair.PrivateKey.Raw
		if len(encValue) > 0 {
			fmt.Println("X0000000")
		} else {
			fmt.Println("1111111")
		}
		fmt.Println(base64.StdEncoding.EncodeToString(encValue))
		fmt.Println("000000000 private")
	}

	/*
		fmt.Println(len(cp.Body.Responses[1].CertifiedKeyPair.PrivateKeyRawValue.FullBytes))
		fmt.Println(len(cp.Body.Responses[1].CertifiedKeyPair.PrivateKeyRawValue.Bytes))
		fmt.Println("PrivateKey")
		ev, err := cp.Body.Responses[1].CertifiedKeyPair.ParsePrivateKey()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(len(ev.Raw))
		fmt.Println(ev.EncValue)
		fmt.Println(base64.StdEncoding.EncodeToString(ev.EncValue.Bytes))
	*/
	cpx, err := ParsePKIBodyCP(asn1Body)
	if err != nil {
		log.Fatal(err)
	}
	for _, cert := range cpx.ExtraCerts {
		fmt.Println(base64.StdEncoding.EncodeToString(cert.Raw))
	}
	fmt.Println(0)
	fmt.Println(base64.StdEncoding.EncodeToString(cpx.Body.Responses[0].CertifiedKeyPair.Cert.Raw))

	fmt.Println(1)
	fmt.Println(base64.StdEncoding.EncodeToString(cpx.Body.Responses[1].CertifiedKeyPair.PrivateKey.EncValue.Bytes))
	fmt.Println(base64.StdEncoding.EncodeToString(cpx.Body.Responses[1].CertifiedKeyPair.Cert.Raw))
	fmt.Println(base64.StdEncoding.EncodeToString(cpx.Body.Responses[1].CertifiedKeyPair.PrivateKey.EncSymmKey.Bytes))
	//0000
	{
		fmt.Println("000000000 private")
		encValue := cp.Body.Responses[1].CertifiedKeyPair.PrivateKey.Raw
		if len(encValue) > 0 {
			fmt.Println("X0000000")
		} else {
			fmt.Println("1111111")
		}
		fmt.Println(base64.StdEncoding.EncodeToString(encValue))
		fmt.Println("000000000 private")
		keyAlgo := cp.Body.Responses[1].CertifiedKeyPair.PrivateKey.KeyAlg
		fmt.Println(keyAlgo)
	}

	for _, resp := range cpx.Body.Responses {
		if resp.OK() {
			priv, cert, err := resp.GetPrivatekeyAndCertificate()
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(priv) // the priv may null, so the cert is the certificate
			fmt.Println(cert)
		}
	}
}
