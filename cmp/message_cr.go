package cmp

import "encoding/asn1"

func NewPKIBodyCRasn1(tmplLst []CertTemplate) (interface{}, error) {
	crMsgLst := make([]CertReqMessage, len(tmplLst))
	for index, tmpl := range tmplLst {
		cr := CertRequest{
			CertReqID:    index,
			CertTemplate: tmpl,
		}
		crMsg := CertReqMessage{
			CertReq: cr,
		}
		crMsgLst[index] = crMsg
	}

	wrap := struct {
		CR interface{}
	}{
		CR: crMsgLst,
	}

	body, err := asn1.MarshalWithParams(wrap, "tag:2,explicit,optional")
	if err != nil {
		return nil, err
	}
	return asn1.RawValue{
		FullBytes: body,
	}, nil
}
