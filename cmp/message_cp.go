package cmp

import (
	"encoding/asn1"
	"errors"
)

type PKIMessageCP struct {
	PKIMessageHead
	Body CertRepMessage `asn1:"explicit,tag:3"`
	PKIMessageFoot
}

func (cp *PKIMessageCP) GetCertWithEncValueLst() ([]*CertWithEncValue, error) {
	ret := make([]*CertWithEncValue, 0)
	for _, resp := range cp.Body.Responses {
		cev, err := resp.GetCertWithEncValue()
		if err != nil {
			return nil, err
		}
		ret = append(ret, cev)
	}
	return ret, nil
}

type pkiMessageCP struct {
	Raw        asn1.RawContent
	Header     PKIHeader
	Body       certRepMessage `asn1:"explicit,tag:3"`
	Protection PKIProtection  `asn1:"explicit,tag:0"`
	ExtraCerts []certificate  `asn1:"tag:1"`
}

func (cp pkiMessageCP) CheckSignature() error {
	if len(cp.ExtraCerts) == 0 {
		return errors.New("no ca pub cert returned")
	}
	certRaw := cp.ExtraCerts[len(cp.ExtraCerts)-1].Raw
	return checkPKIMessageSignature(
		certRaw,
		cp.Header.Raw,
		cp.Body.Raw,
		cp.Protection.Bytes,
		cp.Header.ProtectionAlg,
	)
}

func ParsePKIBodyCP(raw []byte) (*PKIMessageCP, error) {
	cp := pkiMessageCP{}
	_, err := asn1.Unmarshal(raw, &cp)
	if err != nil {
		return nil, err
	}
	if err := cp.CheckSignature(); err != nil {
		return nil, err
	}
	ret := &PKIMessageCP{}
	ret.Raw = cp.Raw
	ret.Header = cp.Header
	body := cp.Body.newCertRepMessage()
	ret.Body = body
	ret.Protection = cp.Protection
	for _, cert := range cp.ExtraCerts {
		x509Cert, err := Certificate{Raw: cert.Raw[:]}.ToX590Certificate()
		if err != nil {
			return nil, err
		}
		ret.ExtraCerts = append(ret.ExtraCerts, x509Cert)
	}

	return ret, nil
}
