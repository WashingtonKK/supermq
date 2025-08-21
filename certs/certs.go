// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package certs

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/absmach/supermq/pkg/errors"
)

type CertType int

const (
	RootCA CertType = iota
	IntermediateCA
	ClientCert
)

const (
	Root    = "RootCA"
	Inter   = "IntermediateCA"
	Client  = "ClientCert"
	Unknown = "Unknown"

	Organization                 = "AbstractMacines"
	emailAddress                 = "info@abstractmachines.rs"
	PrivateKeyBytes              = 2048
	RootCAValidityPeriod         = time.Hour * 24 * 365 // 365 days
	IntermediateCAVAlidityPeriod = time.Hour * 24 * 90  // 90 days
	certValidityPeriod           = time.Hour * 24 * 30  // 30 days
	rCertExpiryThreshold         = time.Hour * 24 * 30  // 30 days
	iCertExpiryThreshold         = time.Hour * 24 * 10  // 10 days
	downloadTokenExpiry          = time.Minute * 5
	PrivateKey                   = "PRIVATE KEY"
	RSAPrivateKey                = "RSA PRIVATE KEY"
	ECPrivateKey                 = "EC PRIVATE KEY"
	PKCS8PrivateKey              = "PKCS8 PRIVATE KEY"
	EDPrivateKey                 = "ED25519 PRIVATE KEY"
)

var (
	serialNumberLimit         = new(big.Int).Lsh(big.NewInt(1), 128)
	ErrNotFound               = errors.New("entity not found")
	ErrConflict               = errors.New("entity already exists")
	ErrCreateEntity           = errors.New("failed to create entity")
	ErrViewEntity             = errors.New("view entity failed")
	ErrGetToken               = errors.New("failed to get token")
	ErrUpdateEntity           = errors.New("update entity failed")
	ErrMalformedEntity        = errors.New("malformed entity specification")
	ErrRootCANotFound         = errors.New("root CA not found")
	ErrIntermediateCANotFound = errors.New("intermediate CA not found")
	ErrCertExpired            = errors.New("certificate expired before renewal")
	ErrCertRevoked            = errors.New("certificate has been revoked and cannot be renewed")
	ErrCertInvalidType        = errors.New("invalid cert type")
	ErrInvalidLength          = errors.New("invalid length of serial numbers")
	ErrPrivKeyType            = errors.New("unsupported private key type")
	ErrPubKeyType             = errors.New("unsupported public key type")
	ErrFailedParse            = errors.New("failed to parse key PEM")
	ErrInvalidIP              = errors.New("invalid IP address")
)

func (c CertType) String() string {
	switch c {
	case RootCA:
		return Root
	case IntermediateCA:
		return Inter
	case ClientCert:
		return Client
	default:
		return Unknown
	}
}

func CertTypeFromString(s string) (CertType, error) {
	switch s {
	case Root:
		return RootCA, nil
	case Inter:
		return IntermediateCA, nil
	case Client:
		return ClientCert, nil
	default:
		return -1, errors.New("unknown cert type")
	}
}

type Cert struct {
	SerialNumber string    `json:"serial_number"`
	CAChain      []string  `json:"ca_chain,omitempty"`
	IssuingCA    string    `json:"issuing_ca,omitempty"`
	Certificate  string    `json:"certificate,omitempty"`
	Key          string    `json:"key,omitempty"`
	ExpiryTime   time.Time `json:"expiry_time"`
	ClientID     string    `json:"entity_id"`
	Revoked      bool      `json:"revoked"`
	Type         CertType  `db:"type"`
	DownloadUrl  string    `db:"-"`
	EntityID     string    `db:"entity_id"`
}

type CertPage struct {
	PageMetadata
	Total        uint64 `json:"total"`
	Offset       uint64 `json:"offset"`
	Limit        uint64 `json:"limit"`
	Certificates []Cert `json:"certificates,omitempty"`
}

type CSR struct {
	CSR        []byte `json:"csr,omitempty"`
	PrivateKey []byte `json:"private_key,omitempty"`
}

type CA struct {
	Type         CertType
	Certificate  *x509.Certificate
	PrivateKey   *rsa.PrivateKey
	SerialNumber string
}

// Repository specifies a Cert persistence API aligned to the current schema.
// Repository specifies a Cert persistence API with no duplicate methods.
type Repository interface {
	// CreateCert inserts a certificate (PK: serial_number).
	CreateCert(ctx context.Context, cert Cert) error

	// RetrieveCert fetches a certificate by serial number.
	RetrieveCert(ctx context.Context, serialNumber string) (Cert, error)

	// GetCAs returns CA certificates. If none provided, defaults to RootCA + IntermediateCA.
	GetCAs(ctx context.Context, caType ...CertType) ([]Cert, error)

	// UpdateCert updates an existing certificate (matched by serial_number).
	UpdateCert(ctx context.Context, cert Cert) error

	// ListCerts paginates certificates; if PageMetadata.EntityID is set, results are filtered to that entity.
	ListCerts(ctx context.Context, pm PageMetadata) (CertPage, error)

	// ListRevokedCerts returns all revoked certificates (any type).
	ListRevokedCerts(ctx context.Context) ([]Cert, error)

	// RemoveCert deletes all certificates for a given entity ID.
	RemoveCert(ctx context.Context, entityID string) error

	// RemoveBySerial deletes a certificate by serial number.
	RemoveBySerial(ctx context.Context, serialID string) error

	// RevokeCertsByEntityID marks all certificates for the entity as revoked and sets expiry_time to now.
	RevokeCertsByEntityID(ctx context.Context, entityID string) error
}

// Service specifies an API that must be fulfilled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type Service interface {
	// IssueCert issues certificate for given client id if access is granted with token
	IssueCert(ctx context.Context, domainID, token, clientID, ttl string) (Cert, error)

	// ListCerts lists certificates issued for a given client ID
	ListCerts(ctx context.Context, clientID string, pm PageMetadata) (CertPage, error)

	// ListSerials lists certificate serial IDs issued for a given client ID
	ListSerials(ctx context.Context, clientID string, pm PageMetadata) (CertPage, error)

	// ViewCert retrieves the certificate issued for a given serial ID
	ViewCert(ctx context.Context, serialID string) (Cert, error)

	// RevokeCert revokes a certificate for a given client ID
	RevokeCert(ctx context.Context, domainID, token, clientID string) (Revoke, error)

	// RevokeBySerial revokes a certificate by its serial number from both PKI and database
	RevokeBySerial(ctx context.Context, serialID string) (Revoke, error)

	// OCSP retrieves the OCSP response for a certificate.
	OCSP(ctx context.Context, serialNumber string) (*Cert, int, *x509.Certificate, error)

	// GetEntityID retrieves the entity ID for a certificate.
	GetEntityID(ctx context.Context, serialNumber string) (string, error)

	// GenerateCRL creates cert revocation list.
	GenerateCRL(ctx context.Context, caType CertType) ([]byte, error)

	// GetChainCA retrieves the chain of CA i.e. root and intermediate cert concat together.
	GetChainCA(ctx context.Context, token string) (Cert, error)

	// RemoveCert deletes a cert for a provided  entityID.
	RemoveCert(ctx context.Context, entityId string) error

	// IssueFromCSR creates a certificate from a given CSR.
	IssueFromCSR(ctx context.Context, entityID, ttl string, csr CSR) (Cert, error)

	// RevokeCerts revokes all certificates for a given entity ID.
	RevokeCerts(ctx context.Context, entityID string) error

	// RetrieveCertDownloadToken generates a certificate download token.
	// The token is needed to download the client certificate.
	RetrieveCertDownloadToken(ctx context.Context, serialNumber string) (string, error)

	// RetrieveCAToken generates a CA download and view token.
	// The token is needed to view and download the CA certificate.
	RetrieveCAToken(ctx context.Context) (string, error)

	// RetrieveCert retrieves a certificate record from the database.
	RetrieveCert(ctx context.Context, token, serialNumber string) (Cert, []byte, error)
}

type PageMetadata struct {
	Total      uint64 `json:"total,omitempty"`
	Offset     uint64 `json:"offset,omitempty"`
	Limit      uint64 `json:"limit,omitempty"`
	CommonName string `json:"common_name,omitempty"`
	Revoked    string `json:"revoked,omitempty"`
	EntityID   string `json:"entity_id,omitempty" db:"entity_id"`
}

var ErrMissingCerts = errors.New("CA path or CA key path not set")

func LoadCertificates(caPath, caKeyPath string) (tls.Certificate, *x509.Certificate, error) {
	if caPath == "" || caKeyPath == "" {
		return tls.Certificate{}, &x509.Certificate{}, ErrMissingCerts
	}

	_, err := os.Stat(caPath)
	if os.IsNotExist(err) || os.IsPermission(err) {
		return tls.Certificate{}, &x509.Certificate{}, err
	}

	_, err = os.Stat(caKeyPath)
	if os.IsNotExist(err) || os.IsPermission(err) {
		return tls.Certificate{}, &x509.Certificate{}, err
	}

	tlsCert, err := tls.LoadX509KeyPair(caPath, caKeyPath)
	if err != nil {
		return tlsCert, &x509.Certificate{}, err
	}

	b, err := os.ReadFile(caPath)
	if err != nil {
		return tlsCert, &x509.Certificate{}, err
	}

	caCert, err := ReadCert(b)
	if err != nil {
		return tlsCert, &x509.Certificate{}, err
	}

	return tlsCert, caCert, nil
}

func ReadCert(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to decode PEM data")
	}

	return x509.ParseCertificate(block.Bytes)
}

type Config struct {
	CommonName         string   `yaml:"common_name"`
	Organization       []string `yaml:"organization"`
	OrganizationalUnit []string `yaml:"organizational_unit"`
	Country            []string `yaml:"country"`
	Province           []string `yaml:"province"`
	Locality           []string `yaml:"locality"`
	StreetAddress      []string `yaml:"street_address"`
	PostalCode         []string `yaml:"postal_code"`
	DNSNames           []string `yaml:"dns_names"`
	IPAddresses        []net.IP `yaml:"ip_addresses"`
	ValidityPeriod     string   `yaml:"validity_period"`
}

type SubjectOptions struct {
	CommonName         string
	Organization       []string `json:"organization"`
	OrganizationalUnit []string `json:"organizational_unit"`
	Country            []string `json:"country"`
	Province           []string `json:"province"`
	Locality           []string `json:"locality"`
	StreetAddress      []string `json:"street_address"`
	PostalCode         []string `json:"postal_code"`
	DnsNames           []string `json:"dns_names"`
	IpAddresses        []net.IP `json:"ip_addresses"`
}
