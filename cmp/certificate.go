package cmp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

type certRepMessage struct {
	Raw       asn1.RawContent
	CaPubs    []certificate `asn1:"tag:1,optional,omitempty"`
	Responses []certResponse
}

func (m certRepMessage) newCertRepMessage() CertRepMessage {
	// ignore CaPubs
	crM := CertRepMessage{}
	crM.Responses = make([]CertResponse, 0)
	for _, res := range m.Responses {
		cRes := res.newCertResponse()
		crM.Responses = append(crM.Responses, *cRes)
	}
	return crM
}

/*
type CertResponse struct {
	Raw              asn1.RawContent
	CertReqID        int
	Status           PKIStatusInfo
	CertifiedKeyPair CertifiedKeyPair
	RespInfo         []byte
}
*/

//  CertResponse ::= SEQUENCE {
//      certReqId           INTEGER,
//      -- to match this response with corresponding request (a value
//      -- of -1 is to be used if certReqId is not specified in the
//      -- corresponding request)
//      status              PKIStatusInfo,
//      certifiedKeyPair    CertifiedKeyPair    OPTIONAL,
//      rspInfo             OCTET STRING        OPTIONAL
//      -- analogous to the id-regInfo-utf8Pairs string defined
//      -- for regInfo in CertReqMsg [CRMF]
//  }
//
//  CertifiedKeyPair ::= SEQUENCE {
//      certOrEncCert       CertOrEncCert,
//      privateKey      [0] EncryptedValue      OPTIONAL,
//      -- see [CRMF] for comment on encoding
//      publicationInfo [1] PKIPublicationInfo  OPTIONAL
//  }
//
//  CertOrEncCert ::= CHOICE {
//  	certificate     [0] CMPCertificate,
//  	encryptedCert   [1] EncryptedValue
//  }

type certResponse struct {
	Raw              asn1.RawContent
	CertReqID        int
	Status           PKIStatusInfo
	CertifiedKeyPair certifiedKeyPair `asn1:"optional"`
	RespInfo         []byte           `asn1:"optional"`
}

func (r certResponse) newCertResponse() *CertResponse {
	ret := &CertResponse{}
	ret.Raw = r.Raw
	ret.CertReqID = r.CertReqID
	ret.Status = r.Status
	ret.CertifiedKeyPair = *(r.CertifiedKeyPair.newCertifiedKeyPair())
	ret.RespInfo = r.RespInfo
	return ret
}

type certifiedKeyPair struct {
	Raw             asn1.RawContent
	CertOrEncCert   certOrEncCert      `asn1:"optional,tag:0"`
	PrivateKey      EncryptedValue     `asn1:"explicit,optional,tag:0"`
	PublicationInfo PKIPublicationInfo `asn1:"explicit,optional,tag:1"`
}

type certOrEncCert struct {
	Cert certificate
}

func (kp certifiedKeyPair) newCertifiedKeyPair() *CertifiedKeyPair {
	ret := &CertifiedKeyPair{}
	ret.Cert = Certificate{
		Raw: kp.CertOrEncCert.Cert.Raw,
	}
	ret.PrivateKey = kp.PrivateKey
	ret.PublicationInfo = kp.PublicationInfo
	return ret
}

type validity struct {
	NotBefore, NotAfter time.Time
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}
