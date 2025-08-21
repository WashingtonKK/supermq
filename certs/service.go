// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/absmach/certs"
	"github.com/absmach/supermq/pkg/errors"
	svcerr "github.com/absmach/supermq/pkg/errors/service"
	mgsdk "github.com/absmach/supermq/pkg/sdk"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/ocsp"
)

var (
	// ErrFailedCertCreation failed to create certificate.
	ErrFailedCertCreation = errors.New("failed to create client certificate")

	// ErrFailedCertRevocation failed to revoke certificate.
	ErrFailedCertRevocation = errors.New("failed to revoke certificate")

	ErrFailedToRemoveCertFromDB = errors.New("failed to remove cert serial from db")

	ErrFailedReadFromPKI = errors.New("failed to read certificate from PKI")

	ErrFailedReadFromDB = errors.New("failed to read certificate from database")
)

var _ Service = (*certsService)(nil)

// Revoke defines the conditions to revoke a certificate.
type Revoke struct {
	RevocationTime time.Time `json:"revocation_time"`
}
type certsService struct {
	sdk            mgsdk.SDK
	certsRepo      Repository
	pki            Agent
	rootCA         *CA
	intermediateCA *CA
}

// New returns new Certs service.
func New(ctx context.Context, sdk mgsdk.SDK, certsRepo Repository, pkiAgent Agent, config *Config) (Service, error) {
	svc := certsService{
		sdk:       sdk,
		pki:       pkiAgent,
		certsRepo: certsRepo,
	}

	// check if root ca should be rotated
	if svc.shouldRotate(RootCA) {
		if err := svc.rotateCA(ctx, RootCA, config); err != nil {
			return &svc, err
		}
	}

	if svc.shouldRotate(IntermediateCA) {
		if err := svc.rotateCA(ctx, IntermediateCA, config); err != nil {
			return &svc, err
		}
	}

	return &svc, nil
}

func (cs *certsService) IssueCert(ctx context.Context, domainID, token, clientID, ttl string) (Cert, error) {
	var err error

	client, err := cs.sdk.Client(ctx, clientID, domainID, token)
	if err != nil {
		return Cert{}, errors.Wrap(ErrFailedCertCreation, err)
	}

	cert, err := cs.pki.Issue(client.ID, ttl, []string{})
	if err != nil {
		return Cert{}, errors.Wrap(ErrFailedCertCreation, err)
	}

	err = cs.certsRepo.CreateCert(ctx, cert)
	if err != nil {
		return Cert{}, errors.Wrap(ErrFailedCertCreation, err)
	}

	return Cert{
		SerialNumber: cert.SerialNumber,
		Certificate:  cert.Certificate,
		Key:          cert.Key,
		ExpiryTime:   cert.ExpiryTime,
		IssuingCA:    cert.IssuingCA,
		CAChain:      cert.CAChain,
		ClientID:     cert.ClientID,
		Revoked:      cert.Revoked,
	}, err
}

func (cs *certsService) RevokeCert(ctx context.Context, domainID, token, clientID string) (Revoke, error) {
	var revoke Revoke
	var err error

	cp, err := cs.certsRepo.ListCerts(ctx, PageMetadata{
		Offset:   0,
		Limit:    10000,
		EntityID: clientID,
	})
	if err != nil {
		return revoke, errors.Wrap(ErrFailedCertRevocation, err)
	}

	for _, c := range cp.Certificates {
		err := cs.pki.Revoke(c.SerialNumber)
		if err != nil {
			return revoke, errors.Wrap(ErrFailedCertRevocation, err)
		}

		c.Revoked = true
		err = cs.certsRepo.UpdateCert(ctx, c)
		if err != nil {
			return revoke, errors.Wrap(ErrFailedReadFromDB, err)
		}

		revoke.RevocationTime = time.Now().UTC()
	}

	return revoke, nil
}

func (cs *certsService) RevokeBySerial(ctx context.Context, serialID string) (Revoke, error) {
	var revoke Revoke

	cert, err := cs.certsRepo.RetrieveCert(ctx, serialID)
	if err != nil {
		return revoke, errors.Wrap(ErrFailedReadFromDB, err)
	}

	err = cs.pki.Revoke(serialID)
	if err != nil {
		return revoke, errors.Wrap(ErrFailedCertRevocation, err)
	}

	cert.Revoked = true
	err = cs.certsRepo.UpdateCert(ctx, cert)
	if err != nil {
		return revoke, errors.Wrap(ErrFailedReadFromDB, err)
	}

	revoke.RevocationTime = time.Now().UTC()
	return revoke, nil
}

func (cs *certsService) ListCerts(ctx context.Context, clientID string, pm PageMetadata) (CertPage, error) {
	pm.EntityID = clientID
	cp, err := cs.certsRepo.ListCerts(ctx, pm)
	if err != nil {
		return CertPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}

	for i, cert := range cp.Certificates {
		vcert, err := cs.pki.View(cert.SerialNumber)
		if err != nil {
			return CertPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
		}
		cp.Certificates[i].Certificate = vcert.Certificate
		cp.Certificates[i].Key = vcert.Key
	}

	return cp, nil
}

func (cs *certsService) ListSerials(ctx context.Context, clientID string, pm PageMetadata) (CertPage, error) {
	pm.EntityID = clientID
	cp, err := cs.certsRepo.ListCerts(ctx, pm)
	if err != nil {
		return CertPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}

	return cp, nil
}

func (cs *certsService) ViewCert(ctx context.Context, serialID string) (Cert, error) {
	cert, err := cs.certsRepo.RetrieveCert(ctx, serialID)
	if err != nil {
		return Cert{}, errors.Wrap(ErrFailedReadFromDB, err)
	}

	vcert, err := cs.pki.View(serialID)
	if err != nil {
		return Cert{}, errors.Wrap(ErrFailedReadFromPKI, err)
	}

	return Cert{
		SerialNumber: cert.SerialNumber,
		Certificate:  vcert.Certificate,
		Key:          vcert.Key,
		ExpiryTime:   vcert.ExpiryTime,
		ClientID:     cert.ClientID,
		Revoked:      cert.Revoked,
	}, nil
}

// RetrieveCertDownloadToken generates a download token for a certificate.
// It verifies the token and serial number, and returns a signed JWT token string.
// The token is valid for 5 minutes.
// Parameters:
//   - ctx: the context.Context object for the request
//   - serialNumber: the serial number of the certificate
//
// Returns:
//   - string: the signed JWT token string
//   - error: an error if the authentication fails or any other error occurs
func (s *certsService) RetrieveCertDownloadToken(ctx context.Context, serialNumber string) (string, error) {
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(downloadTokenExpiry)), Issuer: Organization, Subject: "certs"})
	token, err := jwtToken.SignedString([]byte(serialNumber))
	if err != nil {
		return "", errors.Wrap(certs.ErrGetToken, err)
	}

	return token, nil
}

// RetrieveCAToken generates a download token for a certificate.
// It verifies the token and serial number, and returns a signed JWT token string.
// The token is valid for 5 minutes.
// Parameters:
//   - ctx: the context.Context object for the request
//
// Returns:
//   - string: the signed JWT token string
//   - error: an error if the authentication fails or any other error occurs
func (s *certsService) RetrieveCAToken(ctx context.Context) (string, error) {
	jwtToken := jwt.NewWithClaims(
		jwt.SigningMethodHS256, jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(downloadTokenExpiry)),
			Issuer:    Organization, Subject: "certs",
		},
	)
	token, err := jwtToken.SignedString([]byte(s.intermediateCA.SerialNumber))
	if err != nil {
		return "", errors.Wrap(certs.ErrGetToken, err)
	}

	return token, nil
}

// RenewCert renews a certificate by updating its validity period and generating a new certificate.
// It takes a context, token, and serialNumber as input parameters.
// It returns an error if there is any issue with retrieving the certificate, parsing the certificate,
// parsing the private key, creating a new certificate, or updating the certificate in the repository.
func (s *certsService) RenewCert(ctx context.Context, serialNumber string) error {
	cert, err := s.certsRepo.RetrieveCert(ctx, serialNumber)
	if err != nil {
		return errors.Wrap(ErrViewEntity, err)
	}
	if cert.Revoked {
		return ErrCertRevoked
	}
	pemBlock, _ := pem.Decode([]byte(cert.Certificate))
	oldCert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return err
	}
	if !oldCert.NotAfter.After(time.Now().UTC()) {
		return ErrCertExpired
	}
	oldCert.NotBefore = time.Now().UTC()
	oldCert.NotAfter = time.Now().UTC().Add(certValidityPeriod)
	keyBlock, _ := pem.Decode([]byte(cert.Key))
	privKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}
	if s.intermediateCA.Certificate == nil || s.intermediateCA.PrivateKey == nil {
		return ErrIntermediateCANotFound
	}
	newCertBytes, err := x509.CreateCertificate(
		rand.Reader, oldCert, s.intermediateCA.Certificate, &privKey.PublicKey, s.intermediateCA.PrivateKey,
	)
	if err != nil {
		return err
	}
	cert.Certificate = string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: newCertBytes,
	}))
	cert.ExpiryTime = oldCert.NotAfter
	if err != s.certsRepo.UpdateCert(ctx, cert) {
		return errors.Wrap(ErrUpdateEntity, err)
	}
	return nil
}

// OCSP retrieves the OCSP response for a certificate.
// It takes a context and serialNumber as input parameters.
// It returns the OCSP status, the root CA certificate, the root CA private key, and an error if any issue occurs.
// If the certificate is not found, it returns an OCSP status of Unknown.
// If the certificate is revoked, it returns an OCSP status of Revoked.
// If the server fails to retrieve the certificate, it returns an OCSP status of ServerFailed.
// Otherwise, it returns an OCSP status of Good.
func (s *certsService) OCSP(ctx context.Context, serialNumber string) (*Cert, int, *x509.Certificate, error) {
	cert, err := s.certsRepo.RetrieveCert(ctx, serialNumber)
	if err != nil {
		if errors.Contains(err, ErrNotFound) {
			return nil, ocsp.Unknown, s.intermediateCA.Certificate, nil
		}
		return nil, ocsp.ServerFailed, s.intermediateCA.Certificate, err
	}
	if cert.Revoked {
		return &cert, ocsp.Revoked, s.intermediateCA.Certificate, nil
	}
	return &cert, ocsp.Good, s.intermediateCA.Certificate, nil
}

func (s *certsService) GetEntityID(ctx context.Context, serialNumber string) (string, error) {
	cert, err := s.certsRepo.RetrieveCert(ctx, serialNumber)
	if err != nil {
		return "", errors.Wrap(ErrViewEntity, err)
	}
	return cert.EntityID, nil
}

func (s *certsService) GenerateCRL(ctx context.Context, caType CertType) ([]byte, error) {
	var ca *CA

	switch caType {
	case RootCA:
		if s.rootCA == nil {
			return nil, errors.New("root CA not initialized")
		}
		ca = s.rootCA
	case IntermediateCA:
		if s.intermediateCA == nil {
			return nil, errors.New("intermediate CA not initialized")
		}
		ca = s.intermediateCA
	default:
		return nil, errors.New("invalid CA type")
	}

	revokedCerts, err := s.certsRepo.ListRevokedCerts(ctx)
	if err != nil {
		return nil, err
	}

	revokedCertificates := make([]pkix.RevokedCertificate, len(revokedCerts))
	for i, cert := range revokedCerts {
		serialNumber := new(big.Int)
		serialNumber.SetString(cert.SerialNumber, 10)
		revokedCertificates[i] = pkix.RevokedCertificate{
			SerialNumber:   serialNumber,
			RevocationTime: cert.ExpiryTime,
		}
	}

	// CRL valid for 24 hours
	now := time.Now().UTC()
	expiry := now.Add(24 * time.Hour)

	crlTemplate := &x509.RevocationList{
		Number:              big.NewInt(time.Now().UnixNano()),
		ThisUpdate:          now,
		NextUpdate:          expiry,
		RevokedCertificates: revokedCertificates,
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, ca.Certificate, ca.PrivateKey)
	if err != nil {
		return nil, err
	}

	pemBlock := &pem.Block{
		Type:  "X509 CRL",
		Bytes: crlBytes,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	return pemBytes, nil
}

func (s *certsService) GetChainCA(ctx context.Context, token string) (Cert, error) {
	if _, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{
		Issuer:  Organization,
		Subject: "certs"},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(s.intermediateCA.SerialNumber), nil
		}); err != nil {
		return Cert{}, errors.Wrap(err, ErrMalformedEntity)
	}

	return s.getConcatCAs(ctx)
}

func (s *certsService) IssueFromCSR(ctx context.Context, entityID, ttl string, csr CSR) (Cert, error) {
	block, _ := pem.Decode(csr.CSR)
	if block == nil {
		return Cert{}, errors.New("failed to parse CSR PEM")
	}

	parsedCSR, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return Cert{}, errors.Wrap(ErrMalformedEntity, err)
	}

	if err := parsedCSR.CheckSignature(); err != nil {
		return Cert{}, errors.Wrap(ErrMalformedEntity, err)
	}

	cert, err := s.issue(ctx, entityID, ttl, nil, SubjectOptions{
		CommonName:         parsedCSR.Subject.CommonName,
		Organization:       parsedCSR.Subject.Organization,
		OrganizationalUnit: parsedCSR.Subject.OrganizationalUnit,
		Country:            parsedCSR.Subject.Country,
		Province:           parsedCSR.Subject.Province,
		Locality:           parsedCSR.Subject.Locality,
		StreetAddress:      parsedCSR.Subject.StreetAddress,
		PostalCode:         parsedCSR.Subject.PostalCode,
		IpAddresses:        parsedCSR.IPAddresses,
	}, parsedCSR.PublicKey, nil, parsedCSR.Extensions)
	if err != nil {
		return Cert{}, errors.Wrap(ErrCreateEntity, err)
	}

	return cert, nil
}

func (s *certsService) issue(ctx context.Context, entityID, ttl string, ipAddrs []string, options SubjectOptions, pubKey crypto.PublicKey, privKey crypto.PrivateKey, exts []pkix.Extension) (Cert, error) {
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return Cert{}, err
	}

	subject := subjectFromOpts(options)
	if privKey != nil {
		switch privKey.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, *ed25519.PrivateKey:
			break
		default:
			return Cert{}, errors.Wrap(ErrCreateEntity, ErrPrivKeyType)
		}
	}

	switch pubKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, *ed25519.PublicKey:
		break
	default:
		return Cert{}, errors.Wrap(ErrCreateEntity, ErrPubKeyType)
	}

	// Parse the TTL if provided, otherwise use the default certValidityPeriod.
	validity := certValidityPeriod
	if ttl != "" {
		validity, err = time.ParseDuration(ttl)
		if err != nil {
			return Cert{}, errors.Wrap(ErrMalformedEntity, err)
		}
	}

	var ipArray []net.IP
	ipArray = append(ipArray, s.intermediateCA.Certificate.IPAddresses...)
	ipArray = append(ipArray, options.IpAddresses...)
	for _, ip := range ipAddrs {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			return Cert{}, errors.Wrap(ErrMalformedEntity, ErrInvalidIP)
		}
		ipArray = append(ipArray, parsedIP)
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().Add(validity),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              append(s.intermediateCA.Certificate.DNSNames, options.DnsNames...),
		IPAddresses:           ipArray,
		ExtraExtensions:       exts,
	}

	var privKeyBytes []byte
	var privKeyType string

	if privKey != nil {
		switch key := privKey.(type) {
		case *rsa.PrivateKey:
			privKeyBytes = x509.MarshalPKCS1PrivateKey(key)
			privKeyType = RSAPrivateKey
		case *ecdsa.PrivateKey:
			privKeyBytes, err = x509.MarshalPKCS8PrivateKey(key)
			privKeyType = ECPrivateKey
		case ed25519.PrivateKey:
			privKeyBytes, err = x509.MarshalPKCS8PrivateKey(key)
			privKeyType = PrivateKey
		}

		if err != nil {
			return Cert{}, err
		}
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, s.intermediateCA.Certificate, pubKey, s.intermediateCA.PrivateKey)
	if err != nil {
		return Cert{}, err
	}

	dbCert := Cert{
		SerialNumber: template.SerialNumber.String(),
		EntityID:     entityID,
		ExpiryTime:   template.NotAfter,
		Type:         ClientCert,
		Certificate:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})),
	}

	if privKeyBytes != nil {
		dbCert.Key = string(pem.EncodeToMemory(&pem.Block{Type: privKeyType, Bytes: privKeyBytes}))
	}

	if err = s.certsRepo.CreateCert(ctx, dbCert); err != nil {
		return Cert{}, errors.Wrap(ErrCreateEntity, err)
	}

	return Cert{
		Certificate:  dbCert.Certificate,
		SerialNumber: dbCert.SerialNumber,
		EntityID:     dbCert.EntityID,
		ExpiryTime:   dbCert.ExpiryTime,
		Revoked:      dbCert.Revoked,
		Type:         dbCert.Type,
	}, nil
}

func (s *certsService) RevokeCerts(ctx context.Context, entityID string) error {
	return s.certsRepo.RevokeCertsByEntityID(ctx, entityID)
}

func (s *certsService) getConcatCAs(ctx context.Context) (Cert, error) {
	intermediateCert, err := s.certsRepo.RetrieveCert(ctx, s.intermediateCA.SerialNumber)
	if err != nil {
		return Cert{}, errors.Wrap(ErrViewEntity, err)
	}

	rootCert, err := s.certsRepo.RetrieveCert(ctx, s.rootCA.SerialNumber)
	if err != nil {
		return Cert{}, errors.Wrap(ErrViewEntity, err)
	}

	concat := string(intermediateCert.Certificate) + string(rootCert.Certificate)
	return Cert{
		Certificate: concat,
		ExpiryTime:  intermediateCert.ExpiryTime,
	}, nil
}

func (s *certsService) generateRootCA(ctx context.Context, config Config) (*CA, error) {
	rootKey, err := rsa.GenerateKey(rand.Reader, PrivateKeyBytes)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         config.CommonName,
			Organization:       config.Organization,
			OrganizationalUnit: config.OrganizationalUnit,
			Country:            config.Country,
			Province:           config.Province,
			Locality:           config.Locality,
			StreetAddress:      config.StreetAddress,
			PostalCode:         config.PostalCode,
			SerialNumber:       serialNumber.String(),
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1},
					Value: emailAddress,
				},
			},
		},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().Add(RootCAValidityPeriod),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              config.DNSNames,
		IPAddresses:           config.IPAddresses,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	if err := s.saveCA(ctx, cert, rootKey, RootCA); err != nil {
		return nil, err
	}

	return &CA{
		Type:         RootCA,
		Certificate:  cert,
		PrivateKey:   rootKey,
		SerialNumber: cert.SerialNumber.String(),
	}, nil
}

func (s *certsService) saveCA(ctx context.Context, cert *x509.Certificate, privateKey *rsa.PrivateKey, CertType CertType) error {
	dbCert := Cert{
		Key:          string(pem.EncodeToMemory(&pem.Block{Type: RSAPrivateKey, Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})),
		Certificate:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
		SerialNumber: cert.SerialNumber.String(),
		ExpiryTime:   cert.NotAfter,
		Type:         CertType,
	}
	if err := s.certsRepo.CreateCert(ctx, dbCert); err != nil {
		return errors.Wrap(ErrCreateEntity, err)
	}
	return nil
}

func (s *certsService) createIntermediateCA(ctx context.Context, rootCA *CA, config Config) (*CA, error) {
	intermediateKey, err := rsa.GenerateKey(rand.Reader, PrivateKeyBytes)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         config.CommonName,
			Organization:       config.Organization,
			OrganizationalUnit: config.OrganizationalUnit,
			Country:            config.Country,
			Province:           config.Province,
			Locality:           config.Locality,
			StreetAddress:      config.StreetAddress,
			PostalCode:         config.PostalCode,
			SerialNumber:       serialNumber.String(),
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1},
					Value: emailAddress,
				},
			},
		},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().Add(IntermediateCAVAlidityPeriod),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              config.DNSNames,
		IPAddresses:           config.IPAddresses,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, rootCA.Certificate, &intermediateKey.PublicKey, rootCA.PrivateKey)
	if err != nil {
		return nil, err
	}

	intermediateCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	if err != s.saveCA(ctx, intermediateCert, intermediateKey, IntermediateCA) {
		return nil, err
	}

	intermediateCA := &CA{
		Type:         IntermediateCA,
		Certificate:  intermediateCert,
		PrivateKey:   intermediateKey,
		SerialNumber: serialNumber.String(),
	}

	return intermediateCA, nil
}

func subjectFromOpts(opts SubjectOptions) pkix.Name {
	subject := pkix.Name{
		CommonName: opts.CommonName,
	}

	if len(opts.Organization) > 0 {
		subject.Organization = opts.Organization
	}
	if len(opts.OrganizationalUnit) > 0 {
		subject.OrganizationalUnit = opts.OrganizationalUnit
	}
	if len(opts.Country) > 0 {
		subject.Country = opts.Country
	}
	if len(opts.Province) > 0 {
		subject.Province = opts.Province
	}
	if len(opts.Locality) > 0 {
		subject.Locality = opts.Locality
	}
	if len(opts.StreetAddress) > 0 {
		subject.StreetAddress = opts.StreetAddress
	}
	if len(opts.PostalCode) > 0 {
		subject.PostalCode = opts.PostalCode
	}

	return subject
}

func (s *certsService) rotateCA(ctx context.Context, ctype CertType, config *Config) error {
	switch ctype {
	case RootCA:
		certificates, err := s.certsRepo.GetCAs(ctx)
		if err != nil {
			return err
		}
		for _, cert := range certificates {
			if _, err := s.RevokeBySerial(ctx, cert.SerialNumber); err != nil {
				return err
			}
		}
		newRootCA, err := s.generateRootCA(ctx, *config)
		if err != nil {
			return err
		}
		s.rootCA = newRootCA
		newIntermediateCA, err := s.createIntermediateCA(ctx, newRootCA, *config)
		if err != nil {
			return err
		}
		s.intermediateCA = newIntermediateCA

	case IntermediateCA:
		certificates, err := s.certsRepo.GetCAs(ctx, IntermediateCA)
		if err != nil {
			return err
		}
		for _, cert := range certificates {
			if _, err := s.RevokeBySerial(ctx, cert.SerialNumber); err != nil {
				return err
			}
		}
		newIntermediateCA, err := s.createIntermediateCA(ctx, s.rootCA, *config)
		if err != nil {
			return err
		}
		s.intermediateCA = newIntermediateCA

	default:
		return ErrCertInvalidType
	}

	return nil
}

func (s *certsService) shouldRotate(ctype CertType) bool {
	switch ctype {
	case RootCA:
		if s.rootCA == nil {
			return true
		}
		now := time.Now().UTC()

		// Check if the certificate is expiring soon i.e., within 30 days.
		if now.Add(rCertExpiryThreshold).After(s.rootCA.Certificate.NotAfter) {
			return true
		}
	case IntermediateCA:
		if s.intermediateCA == nil {
			return true
		}
		now := time.Now().UTC()

		// Check if the certificate is expiring soon i.e., within 10 days.
		if now.Add(iCertExpiryThreshold).After(s.intermediateCA.Certificate.NotAfter) {
			return true
		}
	}

	return false
}

func (s *certsService) loadCACerts(ctx context.Context) error {
	certificates, err := s.certsRepo.GetCAs(ctx)
	if err != nil {
		return err
	}

	for _, c := range certificates {
		if c.Type == RootCA {
			rblock, _ := pem.Decode([]byte(c.Certificate))
			if rblock == nil {
				return errors.New("failed to parse certificate PEM")
			}

			rootCert, err := x509.ParseCertificate(rblock.Bytes)
			if err != nil {
				return err
			}
			rkey, _ := pem.Decode([]byte(c.Key))
			if rkey == nil {
				return ErrFailedParse
			}
			rootKey, err := x509.ParsePKCS1PrivateKey(rkey.Bytes)
			if err != nil {
				return err
			}
			s.rootCA = &CA{
				Type:         c.Type,
				Certificate:  rootCert,
				PrivateKey:   rootKey,
				SerialNumber: c.SerialNumber,
			}
		}

		iblock, _ := pem.Decode([]byte(c.Certificate))
		if iblock == nil {
			return errors.New("failed to parse certificate PEM")
		}
		if c.Type == IntermediateCA {
			interCert, err := x509.ParseCertificate(iblock.Bytes)
			if err != nil {
				return err
			}
			ikey, _ := pem.Decode([]byte(c.Key))
			if ikey == nil {
				return ErrFailedParse
			}
			interKey, err := x509.ParsePKCS1PrivateKey(ikey.Bytes)
			if err != nil {
				return err
			}
			s.intermediateCA = &CA{
				Type:         c.Type,
				Certificate:  interCert,
				PrivateKey:   interKey,
				SerialNumber: c.SerialNumber,
			}
		}
	}
	return nil
}

func (s *certsService) RemoveCert(ctx context.Context, entityId string) error {
	return s.certsRepo.RemoveCert(ctx, entityId)
}

// RetrieveCert retrieves a certificate with the specified serial number.
// It requires a valid authentication token to be provided.
// If the token is invalid or expired, an error is returned.
// The function returns the retrieved certificate and any error encountered.
func (s *certsService) RetrieveCert(ctx context.Context, token, serialNumber string) (Cert, []byte, error) {
	if _, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{
		Issuer:  Organization,
		Subject: "certs",
	}, func(token *jwt.Token) (interface{}, error) {
		return []byte(serialNumber), nil
	}); err != nil {
		return Cert{}, []byte{}, errors.Wrap(err, ErrMalformedEntity)
	}
	cert, err := s.certsRepo.RetrieveCert(ctx, serialNumber)
	if err != nil {
		return Cert{}, []byte{}, errors.Wrap(ErrViewEntity, err)
	}
	concat, err := s.getConcatCAs(ctx)
	if err != nil {
		return Cert{}, []byte{}, errors.Wrap(ErrViewEntity, err)
	}

	return cert, []byte(concat.Certificate), nil
}
