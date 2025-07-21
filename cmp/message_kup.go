package cmp

import (
	"encoding/asn1"
	"errors"
)

type PKIMessageKUP struct {
	PKIMessageHead
	Body CertRepMessage `asn1:"explicit,tag:8"`
	PKIMessageFoot
}

func (kup *PKIMessageKUP) GetCertWithEncValueLst() ([]*CertWithEncValue, error) {
	ret := make([]*CertWithEncValue, 0)
	for _, resp := range kup.Body.Responses {
		cev, err := resp.GetCertWithEncValue()
		if err != nil {
			return nil, err
		}
		ret = append(ret, cev)
	}
	return ret, nil
}

type pkiMessageKUP struct {
	Raw        asn1.RawContent
	Header     PKIHeader
	Body       certRepMessage `asn1:"explicit,tag:8"`
	Protection PKIProtection  `asn1:"explicit,tag:0"`
	ExtraCerts []certificate  `asn1:"tag:1"`
}

func (kup pkiMessageKUP) CheckSignature() error {
	if len(kup.ExtraCerts) == 0 {
		return errors.New("no ca pub cert returned")
	}
	certRaw := kup.ExtraCerts[len(kup.ExtraCerts)-1].Raw

	return checkPKIMessageSignature(
		certRaw,
		kup.Header.Raw,
		kup.Body.Raw,
		kup.Protection.Bytes,
		kup.Header.ProtectionAlg,
	)
}

func ParsePKIBodyKUP(raw []byte) (*PKIMessageKUP, error) {
	kup := pkiMessageKUP{}
	_, err := asn1.Unmarshal(raw, &kup)
	if err != nil {
		return nil, err
	}
	if err := kup.CheckSignature(); err != nil {
		return nil, err
	}
	ret := &PKIMessageKUP{}
	ret.Raw = kup.Raw
	ret.Header = kup.Header
	body := kup.Body.newCertRepMessage()
	ret.Body = body
	ret.Protection = kup.Protection
	for _, cert := range kup.ExtraCerts {
		x509Cert, err := Certificate{Raw: cert.Raw[:]}.ToX509Certificate()
		if err != nil {
			return nil, err
		}
		ret.ExtraCerts = append(ret.ExtraCerts, x509Cert)
	}
	return ret, nil
}
