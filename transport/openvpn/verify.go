package openvpn

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"strings"
)

// verifyX509Name enforces the --verify-x509-name directive against the
// server leaf certificate:
//
//	name         the common name must equal name (default)
//	name-prefix  the common name must start with name
//	subject      the whole subject DN, printed the way OpenVPN prints it
//	             ("C=KG, ST=NA, L=Bishkek, O=OpenVPN-TEST, CN=Server-1"),
//	             must equal name
func verifyX509Name(cert *x509.Certificate, name, nameType string) error {
	switch nameType {
	case "", VerifyX509TypeName:
		if cert.Subject.CommonName != name {
			return fmt.Errorf("openvpn server certificate CN %q does not match verify-x509-name %q", cert.Subject.CommonName, name)
		}
	case VerifyX509TypeNamePrefix:
		if !strings.HasPrefix(cert.Subject.CommonName, name) {
			return fmt.Errorf("openvpn server certificate CN %q does not start with verify-x509-name prefix %q", cert.Subject.CommonName, name)
		}
	case VerifyX509TypeSubject:
		subject := x509SubjectString(cert.Subject)
		if subject != name {
			return fmt.Errorf("openvpn server certificate subject %q does not match verify-x509-name %q", subject, name)
		}
	default:
		return fmt.Errorf("unsupported verify-x509-name type %q", nameType)
	}
	return nil
}

// x509AttributeShortNames maps subject attribute OIDs to the short names
// OpenSSL prints with XN_FLAG_FN_SN, which is what OpenVPN uses for the
// subject form of --verify-x509-name (openssl X509_NAME_print_ex with
// XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_SN).
var x509AttributeShortNames = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.4":                    "SN",
	"2.5.4.5":                    "serialNumber",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.9":                    "street",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.12":                   "title",
	"2.5.4.17":                   "postalCode",
	"2.5.4.42":                   "GN",
	"2.5.4.43":                   "initials",
	"2.5.4.46":                   "dnQualifier",
	"2.5.4.65":                   "pseudonym",
	"0.9.2342.19200300.100.1.1":  "UID",
	"0.9.2342.19200300.100.1.25": "DC",
	"1.2.840.113549.1.9.1":       "emailAddress",
}

// x509SubjectString renders a subject DN in OpenVPN's display form: the
// attributes in certificate order, "type=value" pairs joined by ", ".
func x509SubjectString(subject pkix.Name) string {
	parts := make([]string, 0, len(subject.Names))
	for _, attr := range subject.Names {
		oid := attr.Type.String()
		key, ok := x509AttributeShortNames[oid]
		if !ok {
			key = oid
		}
		parts = append(parts, key+"="+fmt.Sprint(attr.Value))
	}
	return strings.Join(parts, ", ")
}
