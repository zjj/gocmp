package cmp

import (
	"encoding/asn1"
	"errors"
	"math/big"
)

type PKIMessageRP struct {
	PKIMessageHead
	Body RevRepContent `asn1:"explicit,optional,tag:12"`
	PKIMessageFoot
}

func (rp *PKIMessageRP) FailInfo() string {
	return string(rp.Body.Status.PKIStatusInfo.FailInfo.Bytes)
}

func (rp *PKIMessageRP) StatusOK() bool {
	return rp.Body.Status.PKIStatusInfo.Status == 0
}

type pkiMessageRP struct {
	Raw        asn1.RawContent
	Header     PKIHeader
	Body       RevRepContent `asn1:"explicit,optional,tag:12"`
	Protection PKIProtection `asn1:"explicit,tag:0"`
	ExtraCerts []certificate `asn1:"tag:1"`
}

func (rp pkiMessageRP) CheckSignature() error {
	if len(rp.ExtraCerts) == 0 {
		return errors.New("no ca pub cert returned")
	}
	certRaw := rp.ExtraCerts[len(rp.ExtraCerts)-1].Raw

	return checkPKIMessageSignature(
		certRaw,
		rp.Header.Raw,
		rp.Body.Raw,
		rp.Protection.Bytes,
		rp.Header.ProtectionAlg,
	)
}

/*
RevRepContent ::= SEQUENCE {
status       SEQUENCE SIZE (1..MAX) OF PKIStatusInfo,
-- in same order as was sent in RevReqContent
revCerts [0] SEQUENCE SIZE (1..MAX) OF CertId
OPTIONAL,
-- IDs for which revocation was requested
-- (same order as status)
crls     [1] SEQUENCE SIZE (1..MAX) OF CertificateList
-- the resulting CRLs (there may be more than one)
}
*/

//type RRD struct {
//	Raw           asn1.RawContent
//	RevRepContent RevRepContent
//}

type InterRevRepContent struct {
	RevRepContent RevRepContent
}

type RevRepContent struct {
	Raw      asn1.RawContent
	RevCerts RevCert `asn1:"explicit,optional,tag:0"`
	Status   InterState
}

type InterState struct {
	PKIStatusInfo PKIStatusInfo
}

//type InterRevCert struct {
//	RevCert RevCert
//}

type RevCert struct {
	DirectoryName InterDirectoryName `asn1:"optional,tag:4"`
	SerialNumber  *big.Int
	//Int int
}

type InterDirectoryName struct {
	InterDirectoryNameSET DirectoryNameSET
}

type DirectoryNameSET struct {
	DirectoryNames []DirectoryName `asn1:"set"`
}

//
type DirectoryName struct {
	Id    asn1.ObjectIdentifier
	Value string
}

func NewPKIBodyRRasn1(tmplLst []CertTemplate, op uint8) (interface{}, error) {
	rrMsgList := make([]RevDetails, len(tmplLst))

	for index, tmpl := range tmplLst {
		rr := RevDetails{
			RevocationReason: asn1.BitString{
				Bytes:     []byte{op},
				BitLength: 8,
			},
			CertDetails: tmpl,
		}
		rrMsgList[index] = rr
	}

	wrap := struct {
		RR interface{}
	}{
		RR: rrMsgList,
	}

	body, err := asn1.MarshalWithParams(wrap, "tag:11,explict")
	if err != nil {
		return nil, err
	}
	return asn1.RawValue{
		FullBytes: body,
	}, nil
}

func ParsePKIBodyRP(raw []byte) (*PKIMessageRP, error) {
	rp := pkiMessageRP{}
	rp.Body.Status.PKIStatusInfo.Status = -1
	_, err := asn1.Unmarshal(raw, &rp)
	if err != nil {
		return nil, err
	}

	if err := rp.CheckSignature(); err != nil {
		return nil, err
	}

	status := rp.Body.Status.PKIStatusInfo
	if status.Status != 0 {
		return nil, errors.New(string(status.FailInfo.Bytes))
	}

	ret := &PKIMessageRP{}
	ret.Raw = rp.Raw
	ret.Header = rp.Header
	ret.Body = rp.Body
	ret.Protection = rp.Protection

	for _, cert := range rp.ExtraCerts {
		x509Cert, err := Certificate{Raw: cert.Raw[:]}.ToX590Certificate()
		if err != nil {
			return nil, err
		}
		ret.ExtraCerts = append(ret.ExtraCerts, x509Cert)
	}

	return ret, nil
}
