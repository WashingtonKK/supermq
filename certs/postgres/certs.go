// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/absmach/supermq/certs"
	"github.com/absmach/supermq/pkg/errors"
	repoerr "github.com/absmach/supermq/pkg/errors/repository"
	"github.com/absmach/supermq/pkg/postgres"
)

var _ certs.Repository = (*certsRepository)(nil)

type certsRepository struct {
	db postgres.Database
}

func NewRepository(db postgres.Database) certs.Repository {
	return &certsRepository{db: db}
}

func (cr certsRepository) RetrieveAll(ctx context.Context, offset, limit uint64) (certs.CertPage, error) {
	pm := certs.PageMetadata{Offset: offset, Limit: limit}
	return cr.ListCerts(ctx, pm)
}

func (cr certsRepository) RetrieveByClient(ctx context.Context, entityID string, pm certs.PageMetadata) (certs.CertPage, error) {
	pm.EntityID = entityID
	return cr.ListCerts(ctx, pm)
}

func (cr certsRepository) Save(ctx context.Context, cert certs.Cert) (string, error) {
	if err := cr.CreateCert(ctx, cert); err != nil {
		return "", err
	}
	return cert.SerialNumber, nil
}

func (cr certsRepository) Update(ctx context.Context, cert certs.Cert) error {
	return cr.UpdateCert(ctx, cert)
}

func (cr certsRepository) Remove(ctx context.Context, entityID string) error {
	return cr.RemoveCert(ctx, entityID)
}

func (cr certsRepository) RemoveBySerial(ctx context.Context, serialID string) error {
	q := `DELETE FROM certs WHERE serial_number = :serial_number`
	p := map[string]any{"serial_number": serialID}
	if _, err := cr.db.NamedExecContext(ctx, q, p); err != nil {
		return errors.Wrap(repoerr.ErrRemoveEntity, err)
	}
	return nil
}

func (cr certsRepository) RetrieveBySerial(ctx context.Context, serial string) (certs.Cert, error) {
	return cr.RetrieveCert(ctx, serial)
}

func (repo certsRepository) CreateCert(ctx context.Context, cert certs.Cert) error {
	q := `
		INSERT INTO certs (serial_number, certificate, key, entity_id, revoked, expiry_time, type)
		VALUES (:serial_number, :certificate, :key, :entity_id, :revoked, :expiry_time, :type)`
	_, err := repo.db.NamedExecContext(ctx, q, toDBCert(cert))
	if err != nil {
		return postgres.HandleError(certs.ErrCreateEntity, err)
	}
	return nil
}

func (repo certsRepository) RetrieveCert(ctx context.Context, serialNumber string) (certs.Cert, error) {
	q := `
		SELECT serial_number, certificate, key, entity_id, revoked, expiry_time, type
		FROM certs WHERE serial_number = $1`
	var dbc dbCert
	if err := repo.db.QueryRowxContext(ctx, q, serialNumber).StructScan(&dbc); err != nil {
		if err == sql.ErrNoRows {
			return certs.Cert{}, errors.Wrap(certs.ErrNotFound, err)
		}
		return certs.Cert{}, errors.Wrap(certs.ErrViewEntity, err)
	}
	return toCert(dbc)
}

func (repo certsRepository) GetCAs(ctx context.Context, caType ...certs.CertType) ([]certs.Cert, error) {
	q := `SELECT serial_number, key, certificate, expiry_time, revoked, type FROM certs WHERE type = ANY($1)`

	var types []string
	if len(caType) == 0 {
		types = []string{certs.RootCA.String(), certs.IntermediateCA.String()}
	} else {
		types = make([]string, len(caType))
		for i, t := range caType {
			types[i] = t.String()
		}
	}

	rows, err := repo.db.QueryContext(ctx, q, types)
	if err != nil {
		return nil, postgres.HandleError(certs.ErrViewEntity, err)
	}
	defer rows.Close()

	var out []certs.Cert
	for rows.Next() {
		var (
			serial string
			key    sql.NullString
			certB  sql.NullString
			exp    sql.NullTime
			rev    sql.NullBool
			tStr   sql.NullString
		)
		if err := rows.Scan(&serial, &key, &certB, &exp, &rev, &tStr); err != nil {
			return nil, errors.Wrap(certs.ErrViewEntity, err)
		}
		c := certs.Cert{
			SerialNumber: serial,
			Key:          key.String,
			Certificate:  certB.String,
			Revoked:      rev.Valid && rev.Bool,
		}
		if exp.Valid {
			c.ExpiryTime = exp.Time
		}
		if tStr.Valid {
			if tt, err := certs.CertTypeFromString(tStr.String); err == nil {
				c.Type = tt
			}
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(certs.ErrViewEntity, err)
	}
	return out, nil
}

func (repo certsRepository) UpdateCert(ctx context.Context, cert certs.Cert) error {
	q := `
		UPDATE certs
		SET certificate = :certificate,
		    key         = :key,
		    revoked     = :revoked,
		    expiry_time = :expiry_time
		WHERE serial_number = :serial_number`
	res, err := repo.db.NamedExecContext(ctx, q, toDBCert(cert))
	if err != nil {
		return postgres.HandleError(certs.ErrUpdateEntity, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return errors.Wrap(certs.ErrUpdateEntity, err)
	}
	if n == 0 {
		return certs.ErrNotFound
	}
	return nil
}

func (repo certsRepository) ListCerts(ctx context.Context, pm certs.PageMetadata) (certs.CertPage, error) {
	base := `SELECT serial_number, revoked, expiry_time, entity_id FROM certs`
	var cond string
	if pm.EntityID != "" {
		cond = fmt.Sprintf(`WHERE entity_id = :entity_id AND type = '%s'`, certs.ClientCert.String())
	} else {
		cond = fmt.Sprintf(`WHERE type = '%s'`, certs.ClientCert.String())
	}
	q := fmt.Sprintf(`%s %s LIMIT :limit OFFSET :offset`, base, cond)

	params := map[string]any{
		"limit":     pm.Limit,
		"offset":    pm.Offset,
		"entity_id": pm.EntityID,
	}

	rows, err := repo.db.NamedQueryContext(ctx, q, params)
	if err != nil {
		return certs.CertPage{}, postgres.HandleError(certs.ErrViewEntity, err)
	}
	defer rows.Close()

	var certsOut []certs.Cert
	for rows.Next() {
		var d dbCert
		if err := rows.StructScan(&d); err != nil {
			return certs.CertPage{}, errors.Wrap(certs.ErrViewEntity, err)
		}
		c, _ := toCert(d)
		certsOut = append(certsOut, c)
	}
	if err := rows.Err(); err != nil {
		return certs.CertPage{}, errors.Wrap(certs.ErrViewEntity, err)
	}

	countQ := fmt.Sprintf(`SELECT COUNT(*) FROM certs %s`, cond)
	total, err := postgres.Total(ctx, repo.db, countQ, params)
	if err != nil {
		return certs.CertPage{}, errors.Wrap(certs.ErrViewEntity, err)
	}
	pm.Total = total
	return certs.CertPage{PageMetadata: pm, Certificates: certsOut}, nil
}

func (repo certsRepository) ListRevokedCerts(ctx context.Context) ([]certs.Cert, error) {
	q := `
		SELECT serial_number, entity_id, expiry_time
		FROM certs
		WHERE revoked = true`
	rows, err := repo.db.QueryContext(ctx, q)
	if err != nil {
		return nil, postgres.HandleError(certs.ErrViewEntity, err)
	}
	defer rows.Close()

	var out []certs.Cert
	for rows.Next() {
		var serial string
		var entityID sql.NullString
		var exp sql.NullTime
		var c certs.Cert
		if err := rows.Scan(&serial, &entityID, &exp); err != nil {
			return nil, postgres.HandleError(certs.ErrViewEntity, err)
		}
		c.SerialNumber = serial
		c.EntityID = entityID.String
		if exp.Valid {
			c.ExpiryTime = exp.Time
		}
		out = append(out, c)
	}
	return out, nil
}

func (repo certsRepository) RemoveCert(ctx context.Context, entityID string) error {
	q := `DELETE FROM certs WHERE entity_id = $1`
	result, err := repo.db.ExecContext(ctx, q, entityID)
	if err != nil {
		return errors.Wrap(certs.ErrViewEntity, err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return certs.ErrNotFound
	}
	return nil
}

func (repo certsRepository) RevokeCertsByEntityID(ctx context.Context, entityID string) error {
	q := `UPDATE certs SET revoked = true, expiry_time = $1 WHERE entity_id = $2`
	result, err := repo.db.ExecContext(ctx, q, time.Now().UTC(), entityID)
	if err != nil {
		return errors.Wrap(certs.ErrUpdateEntity, err)
	}
	ra, err := result.RowsAffected()
	if err != nil {
		return errors.Wrap(certs.ErrUpdateEntity, err)
	}
	if ra == 0 {
		return certs.ErrNotFound
	}
	return nil
}

type dbCert struct {
	SerialNumber string         `db:"serial_number"`
	Certificate  sql.NullString `db:"certificate"`
	Key          sql.NullString `db:"key"`
	EntityID     sql.NullString `db:"entity_id"`
	Revoked      sql.NullBool   `db:"revoked"`
	ExpiryTime   sql.NullTime   `db:"expiry_time"`
	Type         sql.NullString `db:"type"`
}

func toDBCert(c certs.Cert) dbCert {
	var tStr string
	if c.Type.String() != "" {
		tStr = c.Type.String()
	}
	var expNT sql.NullTime
	if !c.ExpiryTime.IsZero() {
		expNT = sql.NullTime{Time: c.ExpiryTime, Valid: true}
	}
	return dbCert{
		SerialNumber: c.SerialNumber,
		Certificate:  sql.NullString{String: c.Certificate, Valid: c.Certificate != ""},
		Key:          sql.NullString{String: c.Key, Valid: c.Key != ""},
		EntityID:     sql.NullString{String: c.EntityID, Valid: c.EntityID != ""},
		Revoked:      sql.NullBool{Bool: c.Revoked, Valid: true},
		ExpiryTime:   expNT,
		Type:         sql.NullString{String: tStr, Valid: tStr != ""},
	}
}

func toCert(d dbCert) (certs.Cert, error) {
	var c certs.Cert
	c.SerialNumber = d.SerialNumber
	c.Certificate = d.Certificate.String
	c.Key = d.Key.String
	c.EntityID = d.EntityID.String
	c.Revoked = d.Revoked.Valid && d.Revoked.Bool
	if d.ExpiryTime.Valid {
		c.ExpiryTime = d.ExpiryTime.Time
	}
	if d.Type.Valid {
		if tt, err := certs.CertTypeFromString(d.Type.String); err == nil {
			c.Type = tt
		}
	}
	return c, nil
}

func applyLimitOffset(query string) string {
	return fmt.Sprintf(`%s
			LIMIT :limit OFFSET :offset`, query)
}
