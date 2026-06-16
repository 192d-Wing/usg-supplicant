// Generator for the outer-tunnel RSA server-cert fixtures (provenance only; not
// compiled by cargo). rcgen cannot produce RSA keys, so we mint a realistic
// RSA-2048 chain — a self-signed RSA CA and an RSA leaf it signs for the test
// server name — mirroring DoD PKI where the RADIUS server cert and its CA are
// RSA. Run from this directory:
//
//	go run gen_rsa_chain.go
//
// Emits DER: rsa_ca.der (trust anchor), rsa_server_leaf.der (server presents),
// rsa_server_key_pkcs8.der (server's private key). Validity is fixed and wide so
// the committed fixtures stay valid in CI; the values are deterministic except
// the keys (RSA keygen is random — regenerating rotates the fixtures, which is
// fine, they are throwaway test material with no secret value).
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"time"
)

func main() {
	notBefore := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "usg-supplicant test RSA CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	must(err)
	caCert, err := x509.ParseCertificate(caDER)
	must(err)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "teap.test.local"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"teap.test.local"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	must(err)

	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	must(err)

	must(os.WriteFile("rsa_ca.der", caDER, 0o644))
	must(os.WriteFile("rsa_server_leaf.der", leafDER, 0o644))
	must(os.WriteFile("rsa_server_key_pkcs8.der", keyDER, 0o644))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
