package cmp

import (
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/zjj/golibkit/certutil"
)

// KeyRecRepContent shall come from keyRecRepContent lower, raw
type KeyRecRepContent struct {
	Raw         asn1.RawContent
	Status      PKIStatusInfo
	NewSigCert  Certificate
	CACerts     []Certificate
	KeyPairHist []CertifiedKeyPair
}

type _keyRecRepContent struct {
	Raw           asn1.RawContent
	Status        PKIStatusInfo
	NewSigCertRaw asn1.RawValue      `asn1:"optional,tag:0,omitempty"`
	CACerts       []certificate      `asn1:"optional,tag:1,omitempty"`
	KeyPairHist   []certifiedKeyPair `asn1:"optional,tag:2,omitempty"`
}

func (c _keyRecRepContent) newKeyRecRepContent() KeyRecRepContent {
	content := KeyRecRepContent{}
	content.Raw = c.Raw
	content.Status = c.Status
	content.NewSigCert = Certificate{Raw: c.NewSigCertRaw.Bytes}

	content.CACerts = make([]Certificate, 0)
	for index := range c.CACerts {
		cert := c.CACerts[index]
		newCert := Certificate{
			Raw: cert.Raw,
		}
		content.CACerts = append(content.CACerts, newCert)
	}

	content.KeyPairHist = make([]CertifiedKeyPair, 0)
	for index := range c.KeyPairHist {
		p := c.KeyPairHist[index]
		pair := p.newCertifiedKeyPair()
		content.KeyPairHist = append(content.KeyPairHist, *pair)
	}

	return content
}

type _pkiMessageKRP struct {
	Raw        asn1.RawContent
	Header     PKIHeader
	Body       _keyRecRepContent `asn1:"explicit,tag:10"`
	Protection PKIProtection     `asn1:"explicit,tag:0"`
	ExtraCerts []certificate     `asn1:"tag:1"`
}

func (krp _pkiMessageKRP) CheckSignature() error {
	if len(krp.ExtraCerts) == 0 {
		return errors.New("no ca pub cert returned")
	}
	certRaw := krp.ExtraCerts[len(krp.ExtraCerts)-1].Raw

	return checkPKIMessageSignature(
		certRaw,
		krp.Header.Raw,
		krp.Body.Raw,
		krp.Protection.Bytes,
		krp.Header.ProtectionAlg,
	)
}

func ParsePKIBodyKRP(raw []byte) (*PKIMessageKRP, error) {
	krp := _pkiMessageKRP{}
	_, err := asn1.Unmarshal(raw, &krp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal krp resp:%s", err.Error())
	}
	if err := krp.CheckSignature(); err != nil {
		return nil, err
	}

	ret := &PKIMessageKRP{}
	ret.Raw = krp.Raw
	ret.Header = krp.Header
	ret.Body = krp.Body.newKeyRecRepContent()
	ret.Protection = krp.Protection
	for _, cert := range krp.ExtraCerts {
		x509Cert, err := Certificate{Raw: cert.Raw[:]}.ToX590Certificate()
		if err != nil {
			return nil, err
		}
		ret.ExtraCerts = append(ret.ExtraCerts, x509Cert)
	}
	return ret, nil
}

// KeyRecRepContent .

type PKIMessageKRP struct {
	PKIMessageHead
	Body KeyRecRepContent
	PKIMessageFoot
}

func (krp *PKIMessageKRP) FailInfo() string {
	return string(krp.Body.Status.FailInfo.Bytes)
}

func (krp *PKIMessageKRP) StatusOK() bool {
	return krp.Body.Status.Status == 0
}

func (krp *PKIMessageKRP) GetCertWithEncValueLst() ([]*CertWithEncValue, error) {
	ret := make([]*CertWithEncValue, 0)

	sigCertRaw := krp.Body.NewSigCert.Raw
	if len(sigCertRaw) == 0 {
		return nil, errors.New("sig cert raw blank")
	}

	x509SigCert, err := certutil.ReadCertificateFromBytes(sigCertRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to read krp sig cert: %s", err.Error())
	}

	cev := &CertWithEncValue{
		EncPriv: nil,
		Cert:    x509SigCert,
	}
	ret = append(ret, cev)

	for index := range krp.Body.KeyPairHist {
		keyPair := krp.Body.KeyPairHist[index]
		cev := &CertWithEncValue{}
		if len(keyPair.PrivateKey.Raw) > 0 {
			cev.EncPriv = &keyPair.PrivateKey
		}

		if len(keyPair.Cert.Raw) > 0 {
			cev.Cert, err = certutil.ReadCertificateFromBytes(keyPair.Cert.Raw)
			if err != nil {
				return nil, err
			}
		}

		ret = append(ret, cev)
	}
	return ret, nil
}
