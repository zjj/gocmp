package cmp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
)

// oidNotInExtensions returns whether an extension with the given oid exists in
// extensions.
func oidInExtensions(oid asn1.ObjectIdentifier, extensions []pkix.Extension) bool {
	for _, e := range extensions {
		if e.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// DN .
type DN struct {
	OID      asn1.ObjectIdentifier
	Name     string
	Code     string
	Critical bool
	Value    []byte
}

var (
	oidExtensionSubjectKeyId          = []int{2, 5, 29, 14}
	oidExtensionKeyUsage              = []int{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage      = []int{2, 5, 29, 37}
	oidExtensionAuthorityKeyId        = []int{2, 5, 29, 35}
	oidExtensionBasicConstraints      = []int{2, 5, 29, 19}
	oidExtensionSubjectAltName        = []int{2, 5, 29, 17}
	oidExtensionCertificatePolicies   = []int{2, 5, 29, 32}
	oidExtensionNameConstraints       = []int{2, 5, 29, 30}
	oidExtensionCRLDistributionPoints = []int{2, 5, 29, 31}
	oidExtensionAuthorityInfoAccess   = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
)

// only dns, email, ipaddress is supported
func marshalSANs(
	dnsNames []string,
	emailAddresses []string,
	ipAddresses []net.IP) (derBytes []byte, err error) {
	var rawValues []asn1.RawValue
	for _, name := range dnsNames {
		rawValues = append(rawValues, asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(name)})
	}
	for _, email := range emailAddresses {
		rawValues = append(rawValues, asn1.RawValue{Tag: 1, Class: 2, Bytes: []byte(email)})
	}
	for _, rawIP := range ipAddresses {
		// If possible, we always want to encode IPv4 addresses in 4 bytes.
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: 7, Class: 2, Bytes: ip})
	}
	return asn1.Marshal(rawValues)
}

/*
	// SubjectAltName ::= GeneralNames
	//
	// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	//
	// GeneralName ::= CHOICE {
	//      otherName                       [0]     OtherName,
	//      rfc822Name                      [1]     IA5String,
	//      dNSName                         [2]     IA5String,
	//      x400Address                     [3]     ORAddress,
	//      directoryName                   [4]     Name,
	//      ediPartyName                    [5]     EDIPartyName,
	//      uniformResourceIdentifier       [6]     IA5String,
	//      iPAddress                       [7]     OCTET STRING,
	//      registeredID                    [8]     OBJECT IDENTIFIER }
*/

func BuildExtensions(sanLst []DN, extLst []DN) (ret []pkix.Extension, err error) {
	ret = make([]pkix.Extension, 10 /* maximum number of elements. */)
	n := 0

	var dNSNames []string
	var emailAddresses []string
	var ipAddresses []net.IP
	for _, dn := range sanLst {
		if len(dn.OID) == 0 { //san
			switch dn.Code {
			case "dNSName":
				dNSNames = append(dNSNames, string(dn.Value))
			case "rfc822Name":
				emailAddresses = append(emailAddresses, string(dn.Value))
			case "iPAddress":
				ip := net.ParseIP(string(dn.Value))
				if ip != nil {
					ipAddresses = append(ipAddresses, ip)
				} else {
					err = fmt.Errorf("ip address illegal: %s", string(dn.Value))
					return
				}
			default:
				err = fmt.Errorf("not supported san name: %s", dn.Code)
				return
			}
		}
	}

	if len(dNSNames) > 0 || len(emailAddresses) > 0 || len(ipAddresses) > 0 {
		ret[n].Id = oidExtensionSubjectAltName
		ret[n].Value, err = marshalSANs(dNSNames, emailAddresses, ipAddresses)
		if err != nil {
			return
		}
		n++
	}
	var extensions []pkix.Extension
	for _, e := range extLst {
		ext := pkix.Extension{
			Id:       e.OID,
			Critical: e.Critical,
			Value:    e.Value,
		}
		extensions = append(extensions, ext)
	}

	return append(ret[:n], extensions...), nil
}

var (
	oidCountry            = []int{2, 5, 4, 6}
	oidOrganization       = []int{2, 5, 4, 10}
	oidOrganizationalUnit = []int{2, 5, 4, 11}
	oidCommonName         = []int{2, 5, 4, 3}
	oidSerialNumber       = []int{2, 5, 4, 5}
	oidLocality           = []int{2, 5, 4, 7}
	oidProvince           = []int{2, 5, 4, 8}
	oidStreetAddress      = []int{2, 5, 4, 9}
	oidPostalCode         = []int{2, 5, 4, 17}
)

func BuildSubject(dnLst []DN) pkix.RDNSequence {
	seq := make(pkix.RDNSequence, 0)

	for _, dn := range dnLst {
		set := make([]pkix.AttributeTypeAndValue, 0)
		av := pkix.AttributeTypeAndValue{
			Type:  dn.OID,
			Value: string(dn.Value),
		}
		set = append(set, av)
		seq = append(seq, set)
	}

	return seq
}
