package cmp

import "encoding/asn1"

func NewPKIBodyKRRasn1(tmplLst []CertTemplate) (interface{}, error) {
	krrMsgLst := make([]CertReqMessage, len(tmplLst))
	for index, tmpl := range tmplLst {
		krr := CertRequest{
			CertReqID:    index,
			CertTemplate: tmpl,
		}
		krrMsg := CertReqMessage{
			CertReq: krr,
		}
		krrMsgLst[index] = krrMsg
	}

	wrap := struct {
		KRR interface{}
	}{
		KRR: krrMsgLst,
	}

	body, err := asn1.MarshalWithParams(wrap, "tag:9,explicit,optional")
	if err != nil {
		return nil, err
	}
	return asn1.RawValue{
		FullBytes: body,
	}, nil
}
