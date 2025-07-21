// this file impls the ra <-> ca
// rfc4211 ?
package cmp

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/tjfoc/gmsm/x509"
	"github.com/zjj/golibkit/certutil"
	"github.com/zjj/golibkit/rand"
)

/*
	PKIStatus ::= INTEGER {
		accepted                (0),
		-- you got exactly what you asked for
		grantedWithMods        (1),
		-- you got something like what you asked for; the
		-- requester is responsible for ascertaining the differences
		rejection              (2),
		-- you don't get it, more information elsewhere in the message
		waiting                (3),
		-- the request body part has not yet been processed; expect to
		-- hear more later (note: proper handling of this status
		-- response MAY use the polling req/rep PKIMessages specified
		-- in Section 5.3.22; alternatively, polling in the underlying
		-- transport layer MAY have some utility in this regard)
		revocationWarning      (4),
		-- this message contains a warning that a revocation is
		-- imminent
		revocationNotification (5),
		-- notification that a revocation has occurred
		keyUpdateWarning       (6)
		-- update already done for the oldCertId specified in
		-- CertReqMsg
	}
*/
type PKIStatus int

const (
	accepted int = iota
	grantedWithMods
	rejection
	waiting
	revocationWarning
	revocationNotification
	keyUpdateWarning
)

/*
PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String

	-- text encoded as UTF-8 String [RFC3629] (note: each
	-- UTF8String MAY include an [RFC3066] language tag
	-- to indicate the language of the contained text
	-- see [RFC2482] for details)
*/
type PKIFreeText []asn1.RawValue

// PKIFailureInfo .
type PKIFailureInfo asn1.BitString

// KeyIdentifier .
type KeyIdentifier []byte

// PKIStatusInfo .
type PKIStatusInfo struct {
	Raw          asn1.RawContent
	Status       PKIStatus
	StatusString PKIFreeText    `asn1:"optional,omitempty"`
	FailInfo     asn1.BitString `asn1:"optional,omitempty"`
}

// ErrorMsgContent .
type ErrorMsgContent struct {
	PKIStatusInfo PKIStatusInfo
	ErrorCode     int         `asn1:"optional"`
	ErrorDetail   PKIFreeText `asn1:"optional"`
}

// PKIHeader .
type PKIHeader struct {
	Raw           asn1.RawContent
	PVNO          int                      `asn1:"default:2"`
	Sender        interface{}              //GeneralName
	Recipient     interface{}              //GeneralName
	MessageTime   time.Time                `asn1:"generalized,explicit,optional,tag:0,omitempty"`
	ProtectionAlg pkix.AlgorithmIdentifier `asn1:"explicit,optional,tag:1,omitempty"`
	SenderKID     []byte                   `asn1:"optional,tag:2,omitempty"`
	RecipKID      []byte                   `asn1:"optional,tag:3,omitempty"`
	TransactionID []byte                   `asn1:"optional,explicit,tag:4,omitempty"`
	SenderNonce   []byte                   `asn1:"optional,tag:5,omitempty"`
	RecipNonce    []byte                   `asn1:"optional,tag:6,omitempty"`
	FreeText      PKIFreeText              `asn1:"explicit,optional,tag:7,omitempty"`
	GeneralInfo   []InfoTypeAndValue       `asn1:"optional,tag:8,omitempty"`
}

func NewPKIHeader() *PKIHeader {
	h := &PKIHeader{}
	h.PVNO = 2

	sender, _ := newSenderDirectoryName()
	h.Sender = *sender
	rec, _ := newRecpDirectoryName()
	h.Recipient = *rec

	uuid, _ := rand.NewUUID()
	h.TransactionID = []byte(uuid)
	h.MessageTime = time.Now().UTC()
	return h
}

func (h *PKIHeader) SetProtectionAlg(alg pkix.AlgorithmIdentifier) {
	h.ProtectionAlg = alg
}

func newDirectoryName(s string) (*asn1.RawValue, error) {
	atv := []pkix.AttributeTypeAndValue{
		{
			Type:  []int{2, 5, 4, 3},
			Value: s,
		},
	}
	name := Name{
		RDNSequence: pkix.RDNSequence{
			atv,
		},
	}
	bys, err := asn1.MarshalWithParams(name, "tag:4,optional")
	if err != nil {
		return nil, err
	}

	return &asn1.RawValue{
		FullBytes: bys,
	}, nil
}

func newSenderDirectoryName() (*asn1.RawValue, error) {
	return newDirectoryName("RA")
}

func newRecpDirectoryName() (*asn1.RawValue, error) {
	return newDirectoryName("CA")
}

type Certificate struct {
	Raw asn1.RawContent
}

func (cert Certificate) ToX509Certificate() (*x509.Certificate, error) {
	return certutil.ReadCertificateFromBytes(cert.Raw)
}

type PKIProtection = asn1.BitString

/*
CertResponse ::= SEQUENCE {
     certReqId           INTEGER,
     -- to match this response with the corresponding request (a value
     -- of -1 is to be used if certReqId is not specified in the
     -- corresponding request)
     status              PKIStatusInfo,
     certifiedKeyPair    CertifiedKeyPair    OPTIONAL,
     rspInfo             OCTET STRING        OPTIONAL
     -- analogous to the id-regInfo-utf8Pairs string defined
     -- for regInfo in CertReqMsg [RFC4211]
 }
*/

type CertWithEncValue struct {
	EncPriv *EncryptedValue
	Cert    *x509.Certificate
}
type CertResponse struct {
	Raw              asn1.RawContent
	CertReqID        int
	Status           PKIStatusInfo
	CertifiedKeyPair CertifiedKeyPair
	RespInfo         []byte
}

func (resp CertResponse) OK() bool {
	return resp.Status.Status == 0
}

func (resp CertResponse) GetCertWithEncValue() (*CertWithEncValue, error) {
	cev := &CertWithEncValue{}
	if len(resp.CertifiedKeyPair.PrivateKey.Raw) > 0 {
		cev.EncPriv = &resp.CertifiedKeyPair.PrivateKey
	}
	var err error
	cev.Cert, err = certutil.ReadCertificateFromBytes(resp.CertifiedKeyPair.Cert.Raw)
	if err != nil {
		return nil, err
	}
	return cev, nil
}

/*
	CertifiedKeyPair ::= SEQUENCE {
	     certOrEncCert       CertOrEncCert,
	     privateKey      [0] EncryptedValue      OPTIONAL,
	     -- see [RFC4211] for comment on encoding
	     publicationInfo [1] PKIPublicationInfo  OPTIONAL }
*/
type CertifiedKeyPair struct {
	Cert Certificate
	//EncCert         Certificate
	PrivateKey      EncryptedValue
	PublicationInfo PKIPublicationInfo
}

/*
	PKIPublicationInfo ::= SEQUENCE {
	    action     INTEGER {
	                   dontPublish (0),
	                   pleasePublish (1) },
	    pubInfos  SEQUENCE SIZE (1..MAX) OF SinglePubInfo OPTIONAL }
	    -- pubInfos MUST NOT be present if action is "dontPublish"
	    -- (if action is "pleasePublish" and pubInfos is omitted,
	    -- "dontCare" is assumed)
*/
type PKIPublicationInfo struct {
	Action   int
	PubInfos []SinglePubInfo `asn1:"optional,omitempty"`
}

/*
	SinglePubInfo ::= SEQUENCE {
	    pubMethod    INTEGER {
	        dontCare    (0),
			x500        (1),
			web         (2),
	        ldap        (3) },
	    pubLocation  GeneralName OPTIONAL }
*/
type SinglePubInfo struct {
	PubMethod   int
	PubLocation GeneralName `asn1:"optional,omitempty"`
}

/*
	CertOrEncCert ::= CHOICE {
		certificate     [0] CMPCertificate,
		encryptedCert   [1] EncryptedValue }
*/
type CertOrEncCert struct {
	Certificate   certificate    `asn1:"tag:0,omitempty"`
	EncryptedCert EncryptedValue `asn1:"tag:1,omitempty"`
}

/*
	EncryptedValue ::= SEQUENCE {
	     intendedAlg   [0] AlgorithmIdentifier{ALGORITHM, {...}}  OPTIONAL,
	     -- the intended algorithm for which the value will be used
	     symmAlg       [1] AlgorithmIdentifier{ALGORITHM, {...}}  OPTIONAL,
	     -- the symmetric algorithm used to encrypt the value
	     encSymmKey    [2] BIT STRING           OPTIONAL,
	     -- the (encrypted) symmetric key used to encrypt the value
	     keyAlg        [3] AlgorithmIdentifier{ALGORITHM, {...}}  OPTIONAL,
	     -- algorithm used to encrypt the symmetric key
	     valueHint     [4] OCTET STRING         OPTIONAL,
	     -- a brief description or identifier of the encValue content
	     -- (may be meaningful only to the sending entity, and used only
	  -- if EncryptedValue might be re-examined by the sending entity

	     -- in the future)
	     encValue       BIT STRING }
	     -- the encrypted value itself
	 -- When EncryptedValue is used to carry a private key (as opposed to
	 -- a certificate), implementations MUST support the encValue field
	 -- containing an encrypted PrivateKeyInfo as defined in [PKCS11],
	 -- section 12.11.  If encValue contains some other format/encoding
	 -- for the private key, the first octet of valueHint MAY be used
	 -- to indicate the format/encoding (but note that the possible values
	 -- of this octet are not specified at this time).  In all cases, the
	 -- intendedAlg field MUST be used to indicate at least the OID of
	 -- the intended algorithm of the private key, unless this information
	 -- is known a priori to both sender and receiver by some other means.
*/
type EncryptedValue struct {
	Raw         asn1.RawContent
	IntendedAlg pkix.AlgorithmIdentifier `asn1:"explicit,tag:0,optional,omitempty"`
	SymmAlg     pkix.AlgorithmIdentifier `asn1:"explicit,tag:1,optional,omitempty"`
	EncSymmKey  asn1.BitString           `asn1:"explicit,tag:2,optional,omitempty"`
	KeyAlg      pkix.AlgorithmIdentifier `asn1:"explicit,tag:3,optional,omitempty"`
	ValueHint   []byte                   `asn1:"explicit,tag:4,optional,omitempty"`
	EncValue    asn1.BitString
}

/*
	CertRequest ::= SEQUENCE {
	    certReqId     INTEGER,        -- ID for matching request and reply
	    certTemplate  CertTemplate, --Selected fields of cert to be issued
	    controls      Controls OPTIONAL } -- Attributes affecting issuance
*/
type CertRequest struct {
	CertReqID    int
	CertTemplate CertTemplate
	Controls     Controls `asn1:"optional,omitempty"`
}

type Controls []pkix.AttributeTypeAndValue

type Version int
type Name struct {
	RDNSequence pkix.RDNSequence
}

/*
	OptionalValidity ::= SEQUENCE {
	      notBefore  [0] Time OPTIONAL,
		  notAfter   [1] Time OPTIONAL }
*/
type OptionalValidity struct {
	NotBefore time.Time `asn1:"generalized,explicit,optional,tag:0"`
	NotAfter  time.Time `asn1:"generalized,explicit,optional,tag:1"`
}

/*
	SubjectPublicKeyInfo  ::=  SEQUENCE  {
	     algorithm            AlgorithmIdentifier,
	     subjectPublicKey     BIT STRING  }
*/
type SubjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

type UniqueIdentifier = asn1.BitString

/*
Extension  ::=  SEQUENCE  {
     extnID      OBJECT IDENTIFIER,
     critical    BOOLEAN DEFAULT FALSE,
     extnValue   OCTET STRING  }
*/
/*
type Extension struct {
	ExtnID    asn1.ObjectIdentifier
	Critical  bool
	ExtnValue []byte
}
*/
type Extensions []pkix.Extension

/*
CertTemplate ::= SEQUENCE {
  version      [0] Version SetPublicKeyWithCSR                  OPTIONAL,
  validity     [4] OptionalValidity      OPTIONAL,
  subject      [5] Name                  OPTIONAL,
  publicKey    [6] SubjectPublicKeyInfo  OPTIONAL,
  issuerUID    [7] UniqueIdentifier      OPTIONAL,
  subjectUID   [8] UniqueIdentifier      OPTIONAL,
  extensions   [9] Extensions            OPTIONAL }
//https://www.ietf.org/rfc/rfc4211.txt
*/

type CertTemplate struct {
	Version      Version  `asn1:"explicit,optional,tag:0"`
	SerialNumber *big.Int `asn1:"explicit,optional,tag:1"`
	//SigningAlg   pkix.AlgorithmIdentifier `asn1:"optional,tag:2"`
	Issuer     Name                 `asn1:"optional,tag:3"`
	Validity   OptionalValidity     `asn1:"optional,explicit,tag:4"`
	Subject    Name                 `asn1:"optional,tag:5"`
	PublicKey  SubjectPublicKeyInfo `asn1:"optional,explicit,tag:6"`
	IssuerUID  UniqueIdentifier     `asn1:"optional,tag:7"`
	SubjectUID UniqueIdentifier     `asn1:"optional,explicit,tag:8"`
	Extensions Extensions           `asn1:"explicit,optional,tag:9"`
}

func NewCertTemplate(serialNumber *big.Int) *CertTemplate {
	t := &CertTemplate{}
	t.SerialNumber = serialNumber
	return t
}

func (tmpl *CertTemplate) SetVersion(version int) {
	tmpl.Version = Version(version)
}

func (tmpl *CertTemplate) SetExtension(ext []pkix.Extension) {
	tmpl.Extensions = ext
}

func (tmpl *CertTemplate) SetValidity(notBefore, notAfter time.Time) {
	validity := OptionalValidity{
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}
	tmpl.Validity = validity
}

func (tmpl *CertTemplate) SetSubject(seq pkix.RDNSequence) {
	tmpl.Subject = Name{seq}
}

func (tmpl *CertTemplate) SetSubjectUID(uid []byte) {
	tmpl.SubjectUID = UniqueIdentifier(asn1.BitString{
		Bytes: uid,
	})
}

func (tmpl *CertTemplate) SetPublicKeyWithRawPublicKeyInfo(der []byte) error {
	var pki SubjectPublicKeyInfo
	_, err := asn1.Unmarshal(der, &pki)
	if err != nil {
		return err
	}
	tmpl.PublicKey = pki
	return nil
}

func (tmpl *CertTemplate) SetPublicKeyWithCSR(der []byte) error {
	publicKeyRaw, err := certutil.GetRawPublicKeyInfoFromCSR(der)
	if err != nil {
		return err
	}
	return tmpl.SetPublicKeyWithRawPublicKeyInfo(publicKeyRaw)
}

// CertReqMessage .
// https://www.ietf.org/rfc/rfc4211.txt
/*
   CertReqMsg ::= SEQUENCE {
      certReq   CertRequest,
      popo       ProofOfPossession  OPTIONAL,
      -- content depends upon key type
      regInfo   SEQUENCE SIZE(1..MAX) of AttributeTypeAndValue OPTIONAL
   }
*/
type CertReqMessage struct {
	CertReq CertRequest
	RegInfo []pkix.AttributeTypeAndValue `asn1:"optional,omitempty"`
}
type ProofOfPossession struct {
}

/*
SubsequentMessage ::= INTEGER {
	encrCert (0),
	challengeResp (1) }
*/

/*
PKMACValue ::= SEQUENCE {
algId  AlgorithmIdentifier,
-- algorithm value shall be PasswordBasedMac {1 2 840 113533 7 66 13}
-- parameter value is PBMParameter
value  BIT STRING }
*/
type PKMACValue struct {
	AlgID pkix.AlgorithmIdentifier
	Value []byte
}

// AuthInfo ignore pop
type AuthInfo struct {
	Sender       *GeneralName `asn1:"tag:0,omitempty"`
	PublicKeyMac *PKMACValue  `asn1:"omitempty"`
}

/*
	ORAddress ::= SEQUENCE {
	   built-in-standard-attributes BuiltInStandardAttributes,
	   built-in-domain-defined-attributes
	                   BuiltInDomainDefinedAttributes OPTIONAL,
	   -- see also teletex-domain-defined-attributes
	   extension-attributes ExtensionAttributes OPTIONAL }
*/
type ORAddress struct {
	StandardAttrs      *BuiltInStandardAttributes
	DomainDefinedAttrs *BuiltInDomainDefinedAttributes `asn1:"optional,omitempty"`
	ExtensionAttris    *ExtensionAttributes            `asn1:"optional,omitempty,set"`
}

/*
	ExtensionAttribute ::=  SEQUENCE {
	   extension-attribute-type [0] IMPLICIT INTEGER
	                   (0..ub-extension-attributes),
	   extension-attribute-value [1]
					   ANY DEFINED BY extension-attribute-type }
*/
type ExtensionAttribute struct {
	Type  int           `asn1:"tag:0"`
	Value asn1.RawValue `asn1:"tag:1"`
}

type ExtensionAttributes []ExtensionAttribute

/*
	BuiltInDomainDefinedAttribute ::= SEQUENCE {
	   type PrintableString (SIZE
	                   (1..ub-domain-defined-attribute-type-length)),
	   value PrintableString (SIZE
					   (1..ub-domain-defined-attribute-value-length)) }
*/
type BuiltInDomainDefinedAttribute struct {
	Type  string
	Value string
}

type BuiltInDomainDefinedAttributes []BuiltInDomainDefinedAttribute

/*
	BuiltInStandardAttributes ::= SEQUENCE {
	   country-name                  CountryName OPTIONAL,
	   administration-domain-name    AdministrationDomainName OPTIONAL,
	   network-address           [0] IMPLICIT NetworkAddress OPTIONAL,
	     -- see also extended-network-address
	   terminal-identifier       [1] IMPLICIT TerminalIdentifier OPTIONAL,
	   private-domain-name       [2] PrivateDomainName OPTIONAL,
	   organization-name         [3] IMPLICIT OrganizationName OPTIONAL,
	     -- see also teletex-organization-name
	   numeric-user-identifier   [4] IMPLICIT NumericUserIdentifier
	                                 OPTIONAL,
	   personal-name             [5] IMPLICIT PersonalName OPTIONAL,
	     -- see also teletex-personal-name
	   organizational-unit-names [6] IMPLICIT OrganizationalUnitNames
	                                 OPTIONAL }
	     -- see also teletex-organizational-unit-names
*/
type BuiltInStandardAttributes struct {
	CountryName              *CountryName              `asn1:"optional,omitempty"`
	AdministrationDomainName *AdministrationDomainName `asn1:"optional,omitempty,application,tag:2"`
	NetworkAddress           *NetworkAddress           `asn1:"tag:0,optional,omitempty"`
	TerminalIdentifier       *TerminalIdentifier       `asn1:"tag:1,optional,omitempty,printable"`
	PrivateDomainName        *PrivateDomainName        `asn1:"tag:2,explicit,optional,omitempty"`
	OrganizationName         *OrganizationName         `asn1:"tag:3,optional,omitempty,printable"`
	NumericUserIdentifier    *NumericUserIdentifier    `asn1:"tag:4,optional,omitempty"`
	PersonalName             *PersonalName             `asn1:"tag:5,optional,omitempty,set"`
	OrganizationalUnitNames  *OrganizationalUnitNames  `asn1:"tag:6,optional,omitempty,printable"`
}

type CountryName struct {
	X121DccCode       string `asn1:"optional,omitempty"`
	Iso3166Alpha2Code string `asn1:"optional,omitempty"`
}

/*
	AdministrationDomainName ::= [APPLICATION 2] CHOICE {
	   numeric   NumericString   (SIZE (0..ub-domain-name-length)),
	   printable PrintableString (SIZE (0..ub-domain-name-length)) }
*/
type AdministrationDomainName string

type NetworkAddress string
type TerminalIdentifier string
type PrivateDomainName string
type OrganizationName string
type NumericUserIdentifier string

/*
	PersonalName ::= SET {
	   surname     [0] IMPLICIT PrintableString
	                    (SIZE (1..ub-surname-length)),
	   given-name  [1] IMPLICIT PrintableString
	                    (SIZE (1..ub-given-name-length)) OPTIONAL,
	   initials    [2] IMPLICIT PrintableString
	                    (SIZE (1..ub-initials-length)) OPTIONAL,
	   generation-qualifier [3] IMPLICIT PrintableString
	                    (SIZE (1..ub-generation-qualifier-length))
						OPTIONAL }
*/
type PersonalName struct {
	SurName             string `asn1:"tag:0"`
	GivenName           string `asn1:"optional,tag:1"`
	Initials            string `asn1:"optional,tag:2"`
	GenerationQualifier string `asn1:"optional,tag:3"`
}

type OrganizationalUnitNames []string

/*
	EDIPartyName ::= SEQUENCE {
		nameAssigner            [0]     DirectoryString OPTIONAL,
		partyName               [1]     DirectoryString }
*/
type EDIPartyName struct {
	Assigner  *DirectoryString `asn1:"tag:0,optional,omitempty"`
	PartyName *DirectoryString `asn1:"tag:1"`
}

/*
	GeneralName ::= CHOICE {
	     otherName                       [0]     AnotherName,
	     rfc822Name                      [1]     IA5String,
	     dNSName                         [2]     IA5String,
	     x400Address                     [3]     ORAddress,
	     directoryName                   [4]     Name,
	     ediPartyName                    [5]     EDIPartyName,
	     uniformResourceIdentifier       [6]     IA5String,
	     iPAddress                       [7]     OCTET STRING,
		 registeredID                    [8]     OBJECT IDENTIFIER }
*/
type GeneralName struct {
	Raw                       asn1.RawContent
	OtherName                 *AnotherName          `asn1:"tag:0,optional,omitempty"`
	RFC822Name                *string               `asn1:"tag:1,ia5,optional,omitempty"`
	DNSName                   *string               `asn1:"tag:2,ia5,optional,omitempty"`
	X400Address               *ORAddress            `asn1:"tag:3,optional,omitempty"`
	DirectoryName             Name                  `asn1:"tag:4,optional,omitempty"`
	EdiPartyName              *EdiPartyName         `asn1:"tag:5,optional,omitempty"`
	UniformResourceIdentifier string                `asn1:"tag:6,ia5,optional,omitempty"`
	IPAddress                 []byte                `asn1:"tag:7,optional,omitempty"`
	RegisteredID              asn1.ObjectIdentifier `asn1:"tag:8,optional,omitempty"`
}

/*
	DirectoryString ::= CHOICE {
	      teletexString           TeletexString (SIZE (1N..MAX)),
	      printableString         PrintableString (SIZE (1..MAX)),
	      universalString         UniversalString (SIZE (1..MAX)),
	      utf8String              UTF8String (SIZE (1..MAX)),
	      bmpString               BMPString (SIZE (1..MAX)) }
*/
type DirectoryString string

/*
	EDIPartyName ::= SEQUENCE {
	     nameAssigner            [0]     DirectoryString OPTIONAL,
	     partyName               [1]     DirectoryString }
*/
type EdiPartyName struct {
	NameAssigner string `asn1:"optional,tag:0"`
	PartyName    DirectoryString
}

/*
	AnotherName ::= SEQUENCE {
	     type-id    OBJECT IDENTIFIER,
		 value      [0] EXPLICIT ANY DEFINED BY type-id }
*/
type AnotherName struct {
	typeID asn1.ObjectIdentifier
	Value  asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type CertReqMessages []CertReqMessage

/*
	CertificationRequestInfo ::= SEQUENCE {
	     version       INTEGER { v1(0) } (v1,...),
	     subject       Name,
	     subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
	     attributes    [0] Attributes{{ CRIAttributes }}
	}
*/
type CertificationRequestInfo struct {
	Version       int `asn1:"default:0"`
	Subject       Name
	SubjectPKInfo SubjectPublicKeyInfo
	Attributes    []Attribute `asn1:"tag:0,set"`
}

/*
	Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
	      type   ATTRIBUTE.&id({IOSet}),
	      values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
	}
*/
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

/*
	CertificationRequest ::= SEQUENCE {
	     certificationRequestInfo CertificationRequestInfo,
	     signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
	     signature          BIT STRING
	}
*/
type CertificationRequest struct {
	CertificationRequestInfo CertificationRequestInfo
	SignatureAlgorithm       pkix.AlgorithmIdentifier
	Signature                asn1.BitString
}

/*
	CertRepMessage ::= SEQUENCE {
	    caPubs       [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
	                  OPTIONAL,
	    response         SEQUENCE OF CertResponse }
*/
type CertRepMessage struct {
	Raw       asn1.RawContent
	CAPubs    []Certificate `asn1:"tag:1,optional,omitempty"`
	Responses []CertResponse
}

/*
	RevDetails ::= SEQUENCE {
	     certDetails         CertTemplate,
	     -- allows requester to specify as much as they can about
	     -- the cert. for which revocation is requested
	     -- (e.g., for cases in which serialNumber is not available)
	     crlEntryDetails     Extensions       OPTIONAL
	     -- requested crlEntryExtensions
	 }
*/
type RevDetails struct {
	CertDetails      CertTemplate
	CRLEntryDetails  *Extensions `asn1:"optional,omitempty"`
	RevocationReason asn1.BitString
}

/*
RevReqContent ::= SEQUENCE OF RevDetails
*/
type RevReqContent []RevDetails

// PKIMessage .
type PKIMessage struct {
	Raw        asn1.RawContent
	Header     PKIHeader
	Body       interface{}   // PKIBody
	Protection PKIProtection `asn1:"explicit,optional,tag:0,omitempty"`
	ExtraCerts []Certificate `asn1:"tag:1,omitempty"`
}

func (msg *PKIMessage) SetBody(body interface{}) {
	msg.Body = body
}

func (msg *PKIMessage) SetProtection(b []byte) {
	sig := b[:]
	p := asn1.BitString{
		Bytes:     sig,
		BitLength: len(sig) * 8,
	}
	msg.Protection = p
}

func (msg *PKIMessage) SerializeAsn1() ([]byte, error) {
	return asn1.Marshal(*msg)
}

func (msg *PKIMessage) SerializeB64() (string, error) {
	asn1Bytes, err := msg.SerializeAsn1()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(asn1Bytes), nil
}

// SignBy .
// the algo could only be sm2.SHA256WithRSA, sm2.SM2WithSM3
// so we could ignore rsapss
func (msg *PKIMessage) SignBy(priv crypto.Signer) error {
	toSignData := struct {
		Header interface{}
		Body   interface{}
	}{
		msg.Header,
		msg.Body,
	}
	digest, err := asn1.Marshal(toSignData)
	if err != nil {
		return err
	}
	algo := certutil.GetSignatureAlgorithmFromAI(msg.Header.ProtectionAlg)
	if algo == x509.UnknownSignatureAlgorithm {
		return errors.New("UnknownSignatureAlgorithm")
	}
	signature, err := certutil.SignMsgByPrivateKey(algo, digest, priv)
	if err != nil {
		return err
	}
	msg.SetProtection(signature)
	return nil
}

type PKIMessageHead struct {
	Raw    asn1.RawContent
	Header PKIHeader
}

type PKIMessageFoot struct {
	Protection PKIProtection       `asn1:"explicit,optional,tag:0,omitempty"`
	ExtraCerts []*x509.Certificate `asn1:"tag:1"`
}

func (msg *PKIMessageFoot) VerifyByRoot(pool *x509.CertPool) error {
	if len(msg.ExtraCerts) > 0 {
		for index := range msg.ExtraCerts {
			cert := msg.ExtraCerts[index]
			opt := x509.VerifyOptions{
				Roots:     pool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			}
			if _, err := cert.Verify(opt); err != nil {
				return fmt.Errorf("failed to verify cert chain by root ca: index:%d %s", index, err.Error())
			}
			// if the last cert, return
			if index == len(msg.ExtraCerts)-1 {
				return nil
			}
			pool = x509.NewCertPool()
			pool.AddCert(cert)
		}
		return nil
	}
	return errors.New("no ca cert in extra certs field")
}

func checkPKIMessageSignature(certRaw, headRaw, bodyRaw, sig []byte, algo pkix.AlgorithmIdentifier) error {
	x509Cert, err := certutil.ReadCertificateFromBytes(certRaw)
	if err != nil {
		return err
	}

	signPart := struct {
		Header asn1.RawValue
		Body   asn1.RawValue
	}{
		Header: asn1.RawValue{
			FullBytes: headRaw,
		},
		Body: asn1.RawValue{
			FullBytes: bodyRaw,
		},
	}

	toSign, err := asn1.Marshal(signPart)
	if err != nil {
		return err
	}
	sigAlgo := certutil.GetSignatureAlgorithmFromAI(algo)
	err = certutil.CheckSignatureByCert(sigAlgo, toSign, sig, x509Cert)
	if err != nil {
		return fmt.Errorf("failed to check cmp signature: %s", err.Error())
	}
	return nil
}

// InfoTypeAndValue represents an information type and value pair as defined in RFC 4210
/*
InfoTypeAndValue ::= SEQUENCE {
    infoType               OBJECT IDENTIFIER,
    infoValue              ANY DEFINED BY infoType  OPTIONAL
}
*/
type InfoTypeAndValue struct {
	InfoType  asn1.ObjectIdentifier
	InfoValue asn1.RawValue `asn1:"optional"`
}
