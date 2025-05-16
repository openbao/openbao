// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"net/url"
)

func protoOIDToASN1(oid *ObjectIdentifier) asn1.ObjectIdentifier {
	if oid == nil {
		return nil
	}

	arcsU32 := oid.GetArc() // []uint32
	arcInt := make(asn1.ObjectIdentifier, len(arcsU32))

	for i, v := range arcsU32 {
		arcInt[i] = int(v) // uint32 -> int
	}
	return arcInt
}

func ProtoNameToPKIX(n *PKIX_Name) pkix.Name {
	if n == nil {
		return pkix.Name{}
	}

	return pkix.Name{
		CommonName:         n.GetCommonName(),
		SerialNumber:       n.GetSerialNumber(),
		Country:            n.GetCountry(),
		Organization:       n.GetOrganization(),
		OrganizationalUnit: n.GetOrganizationUnit(),
		Locality:           n.GetLocality(),
		Province:           n.GetProvince(),
		StreetAddress:      n.GetStreetAddress(),
		PostalCode:         n.GetPostalCode(),
	}
}

func protoToOID(p *OID) (x509.OID, error) {
	if p == nil {
		return x509.OID{}, nil
	}

	return x509.OIDFromInts(p.Arc)
}

// protoToPKIXExt converts []int -> asn1.ObjectIdentifier
func protoToPKIXExt(e *PKIX_Extension) pkix.Extension {
	var oid asn1.ObjectIdentifier
	for _, v := range e.Id {
		oid = append(oid, int(v))
	}
	return pkix.Extension{
		Id:       oid,
		Critical: e.GetCritical(),
		Value:    e.GetValue(), // already []byte
	}
}

// protoIPSliceToNet converts []*Net_IP  -> x509 []net.IP
func protoIPSliceToNet(in []*Net_IP) ([]net.IP, error) {
	out := make([]net.IP, 0, len(in))
	for _, p := range in {
		if p == nil {
			continue
		}
		b := p.GetIP() // []byte
		if len(b) == 0 {
			continue // or return an error
		}
		ip := net.IP(b)
		if ip.To4() == nil && ip.To16() == nil {
			return nil, fmt.Errorf("invalid IP bytes: %x", b)
		}
		out = append(out, ip)
	}
	return out, nil
}

// protoURLSliceToStd converts []*Url_URL -> x509 []*url.URL.
func protoURLSliceToURL(in []*Url_URL) ([]*url.URL, error) {
	out := make([]*url.URL, 0, len(in))

	for _, p := range in {
		if p == nil {
			continue
		}

		u := &url.URL{
			Scheme:      p.GetScheme(),
			Opaque:      p.GetOpaque(),
			Host:        p.GetHost(),
			Path:        p.GetPath(),
			RawPath:     p.GetRawPath(),
			ForceQuery:  p.GetForceQuery(),
			RawQuery:    p.GetRawQuery(),
			Fragment:    p.GetFragment(),
			RawFragment: p.GetRawFragment(),
		}

		if ui := p.GetUser(); ui != nil {
			name := ui.GetUsername()
			if pw := ui.GetPassword(); ui.GetPasswordSet() {
				u.User = url.UserPassword(name, pw)
			} else {
				u.User = url.User(name)
			}
		}

		out = append(out, u)
	}
	return out, nil
}

// protoIPNetSliceToIPNet converts []*Net_IPNet  -> x509 []net.IPNet
func protoIPNetSliceToIPNet(in []*Net_IPNet) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(in))
	for _, p := range in {
		if p == nil {
			continue
		}
		ip := net.IP(p.GetIP().GetIP()) // []byte -> net.IP
		m := net.IPMask(p.GetMask().GetIPMask())
		if len(ip) == 0 || len(m) == 0 {
			return nil, fmt.Errorf("empty ip or mask")
		}
		out = append(out, &net.IPNet{IP: ip, Mask: m})
	}
	return out, nil
}

// protoToPolicyMappings converts proto *PolicyMapping -> x509.PolicyMapping
func protoToPolicyMappings(in []*PolicyMapping) ([]x509.PolicyMapping, error) {
	out := make([]x509.PolicyMapping, 0, len(in))

	for _, pm := range in {
		if pm == nil {
			continue
		}
		iss, err := protoToOID(pm.GetIssuerDomainPolicy())
		if err != nil {
			return nil, fmt.Errorf("issuer OID: %w", err)
		}
		subj, err := protoToOID(pm.GetSubjectDomainPolicy())
		if err != nil {
			return nil, fmt.Errorf("subject OID: %w", err)
		}
		out = append(out, x509.PolicyMapping{
			IssuerDomainPolicy:  iss,
			SubjectDomainPolicy: subj,
		})
	}
	return out, nil
}

// CertProtoToX509 converts the protobuf message produced by CEL into an
// x509.Certificate. If tpl.Raw (full DER) is present we simply parse it;
// otherwise we construct a certificate struct from the decoded fields.
func CertProtoToX509(tpl *CertTemplate) (*x509.Certificate, error) {
	if tpl == nil {
		return nil, fmt.Errorf("template is nil")
	}

	// Otherwise build the struct
	var policyIdentifiers []asn1.ObjectIdentifier
	for _, o := range tpl.GetPolicyIdentifiers() {
		policyIdentifiers = append(policyIdentifiers, protoOIDToASN1(o))
	}

	var unhandledCriticalExtensions []asn1.ObjectIdentifier
	for _, o := range tpl.GetUnhandledCriticalExtensions() {
		unhandledCriticalExtensions = append(unhandledCriticalExtensions, protoOIDToASN1(o))
	}

	var extKeyUsage []x509.ExtKeyUsage
	for _, v := range tpl.GetExtKeyUsage() {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsage(v)) // int32 -> ExtKeyUsage
	}

	var unknownExtKeyUsage []asn1.ObjectIdentifier
	for _, o := range tpl.GetUnknownExtKeyUsage() {
		unknownExtKeyUsage = append(unknownExtKeyUsage, protoOIDToASN1(o))
	}

	var policies []x509.OID
	for _, o := range tpl.Policies {
		po, err := protoToOID(o)
		if err != nil {
			return nil, fmt.Errorf("bad policy OID: %w", err)
		}
		policies = append(policies, po)
	}

	var exts []pkix.Extension
	for _, e := range tpl.GetExtensions() {
		exts = append(exts, protoToPKIXExt(e))
	}

	var extraExts []pkix.Extension
	for _, e := range tpl.GetExtraExtensions() {
		exts = append(exts, protoToPKIXExt(e))
	}

	ips, err := protoIPSliceToNet(tpl.GetIPAddresses())
	if err != nil {
		return nil, fmt.Errorf("bad IP address: %w", err)
	}

	uris, err := protoURLSliceToURL(tpl.GetURIs())
	if err != nil {
		return nil, fmt.Errorf("bad URI: %w", err)
	}

	permittedIPRanges, err := protoIPNetSliceToIPNet(tpl.GetPermittedIPRanges())
	if err != nil {
		return nil, fmt.Errorf("bad permitted IP range: %w", err)
	}

	excludedIPRanges, err := protoIPNetSliceToIPNet(tpl.GetExcludedIPRanges())
	if err != nil {
		return nil, fmt.Errorf("bad permitted IP range: %w", err)
	}

	policyMappings, err := protoToPolicyMappings(tpl.GetPolicyMappings())
	if err != nil {
		return nil, fmt.Errorf("bad policy mappings range: %w", err)
	}

	cert := &x509.Certificate{
		Version:                     int(tpl.GetVersion()),
		Subject:                     ProtoNameToPKIX(tpl.GetSubject()),
		NotBefore:                   tpl.GetNotBefore().AsTime(),
		NotAfter:                    tpl.GetNotAfter().AsTime(),
		KeyUsage:                    x509.KeyUsage(tpl.GetKeyUsage()),
		Extensions:                  exts,
		ExtraExtensions:             extraExts,
		UnhandledCriticalExtensions: unhandledCriticalExtensions,
		ExtKeyUsage:                 extKeyUsage,
		UnknownExtKeyUsage:          unknownExtKeyUsage,
		BasicConstraintsValid:       tpl.GetBasicConstraintsValid(),
		IsCA:                        tpl.GetIsCA(),
		MaxPathLen:                  int(tpl.GetMaxPathLen()),
		MaxPathLenZero:              tpl.GetMaxPathLenZero(),
		SubjectKeyId:                tpl.GetSubjectKeyId(),
		DNSNames:                    tpl.GetDNSNames(),
		EmailAddresses:              tpl.GetEmailAddresses(),
		IPAddresses:                 ips,
		URIs:                        uris,
		PermittedDNSDomainsCritical: tpl.GetPermittedDNSDomainsCritical(),
		PermittedDNSDomains:         tpl.GetPermittedDNSDomains(),
		ExcludedDNSDomains:          tpl.GetExcludedDNSDomains(),
		PermittedIPRanges:           permittedIPRanges,
		ExcludedIPRanges:            excludedIPRanges,
		PermittedEmailAddresses:     tpl.GetPermittedEmailAddresses(),
		ExcludedEmailAddresses:      tpl.GetExcludedEmailAddresses(),
		PermittedURIDomains:         tpl.GetPermittedURIDomains(),
		ExcludedURIDomains:          tpl.GetExcludedURIDomains(),
		PolicyIdentifiers:           policyIdentifiers,
		Policies:                    policies,
		InhibitAnyPolicy:            int(tpl.GetInhibitAnyPolicy()),
		InhibitAnyPolicyZero:        tpl.GetInhibitAnyPolicyZero(),
		InhibitPolicyMapping:        int(tpl.GetInhibitPolicyMapping()),
		InhibitPolicyMappingZero:    tpl.GetInhibitPolicyMappingZero(),
		RequireExplicitPolicy:       int(tpl.GetRequireExplicitPolicy()),
		RequireExplicitPolicyZero:   tpl.GetRequireExplicitPolicyZero(),
		PolicyMappings:              policyMappings,
	}

	// Parse public key if RawSubjectPublicKeyInfo supplied
	if len(cert.RawSubjectPublicKeyInfo) > 0 {
		pub, err := x509.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
		if err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}
		cert.PublicKey = pub
	}

	return cert, nil
}
