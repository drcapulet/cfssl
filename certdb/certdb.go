package certdb

import (
	"fmt"
	"time"

	cferr "github.com/cloudflare/cfssl/errors"

	"github.com/jmoiron/sqlx"
	"github.com/kisielk/sqlstruct"
)

// Match to sqlx
func init() {
	sqlstruct.TagName = "db"
}

// CertificateRecord encodes a certificate and its metadata
// that will be recorded in a database.
type CertificateRecord struct {
	Serial    string    `db:"serial"`
	CALabel   string    `db:"ca_label"`
	Status    string    `db:"status"`
	Reason    int       `db:"reason"`
	Expiry    time.Time `db:"expiry"`
	RevokedAt time.Time `db:"revoked_at"`
	PEM       string    `db:"pem"`
}

// OCSPRecord encodes a OCSP response body and its metadata
// that will be recorded in a database.
type OCSPRecord struct {
	Serial string    `db:"serial"`
	Body   string    `db:"body"`
	Expiry time.Time `db:"expiry"`
}

const (
	insertSQL = `
INSERT INTO certificates (serial, ca_label, status, reason, expiry, revoked_at, pem)
	VALUES (:serial, :ca_label, :status, :reason, :expiry, :revoked_at, :pem);`

	selectSQL = `
SELECT %s FROM certificates
	WHERE (serial = ?);`

	selectAllSQL = `
SELECT %s FROM certificates;`

	selectAllUnexpiredSQL = `
SELECT %s FROM certificates
WHERE CURRENT_TIMESTAMP < expiry;`

	updateRevokeSQL = `
UPDATE certificates
	SET status='revoked', revoked_at=CURRENT_TIMESTAMP, reason=:reason
	WHERE (serial = :serial);`

	insertOCSPSQL = `
INSERT INTO ocsp_responses (serial, body, expiry)
    VALUES (:serial, :body, :expiry);`

	updateOCSPSQL = `
UPDATE ocsp_responses
    SET expiry=:expiry, body=:body
	WHERE (serial = :serial);`

	selectAllUnexpiredOCSPSQL = `
SELECT %s FROM ocsp_responses
WHERE CURRENT_TIMESTAMP < expiry;`

	selectOCSPSQL = `
SELECT %s FROM ocsp_responses
    WHERE (serial = ?);`
)

func wrapCertStoreError(err error) error {
	if err != nil {
		return cferr.Wrap(cferr.CertStoreError, cferr.Unknown, err)
	}
	return nil
}

// InsertCertificate puts a CertificateRecord into db.
func InsertCertificate(db *sqlx.DB, cr *CertificateRecord) error {
	res, err := db.NamedExec(insertSQL, &CertificateRecord{
		Serial:    cr.Serial,
		CALabel:   cr.CALabel,
		Status:    cr.Status,
		Reason:    cr.Reason,
		Expiry:    cr.Expiry.UTC(),
		RevokedAt: cr.RevokedAt.UTC(),
		PEM:       cr.PEM,
	})
	if err != nil {
		return wrapCertStoreError(err)
	}

	numRowsAffected, err := res.RowsAffected()

	if numRowsAffected == 0 {
		return cferr.Wrap(cferr.CertStoreError, cferr.InsertionFailed, fmt.Errorf("failed to insert the certificate record"))
	}

	if numRowsAffected != 1 {
		return wrapCertStoreError(fmt.Errorf("%d rows are affected, should be 1 row", numRowsAffected))
	}

	return err
}

// GetCertificate gets a CertificateRecord indexed by serial.
func GetCertificate(db *sqlx.DB, serial string) (*CertificateRecord, error) {
	cr := &CertificateRecord{}
	err := db.Get(cr, fmt.Sprintf(db.Rebind(selectSQL), sqlstruct.Columns(*cr)), serial)
	if err != nil {
		return nil, wrapCertStoreError(err)
	}

	return cr, nil
}

// GetUnexpiredCertificates gets all unexpired certificate from db.
func GetUnexpiredCertificates(db *sqlx.DB) (crs []CertificateRecord, err error) {
	crs = []CertificateRecord{}
	err = db.Select(&crs, fmt.Sprintf(db.Rebind(selectAllUnexpiredSQL), sqlstruct.Columns(CertificateRecord{})))
	if err != nil {
		return nil, wrapCertStoreError(err)
	}

	return crs, nil
}

// RevokeCertificate updates a certificate with a given serial number and marks it revoked.
func RevokeCertificate(db *sqlx.DB, serial string, reasonCode int) error {
	result, err := db.NamedExec(updateRevokeSQL, &CertificateRecord{
		Reason: reasonCode,
		Serial: serial,
	})

	if err != nil {
		return wrapCertStoreError(err)
	}

	numRowsAffected, err := result.RowsAffected()

	if numRowsAffected == 0 {
		return cferr.Wrap(cferr.CertStoreError, cferr.RecordNotFound, fmt.Errorf("failed to revoke the certificate: certificate not found"))
	}

	if numRowsAffected != 1 {
		return wrapCertStoreError(fmt.Errorf("%d rows are affected, should be 1 row", numRowsAffected))
	}

	return err
}

// InsertOCSP puts a new OCSPRecord into the db.
func InsertOCSP(db *sqlx.DB, rr *OCSPRecord) error {
	res, err := db.NamedExec(insertOCSPSQL, &OCSPRecord{
		Serial: rr.Serial,
		Body:   rr.Body,
		Expiry: rr.Expiry.UTC(),
	})
	if err != nil {
		return wrapCertStoreError(err)
	}

	numRowsAffected, err := res.RowsAffected()

	if numRowsAffected == 0 {
		return cferr.Wrap(cferr.CertStoreError, cferr.InsertionFailed, fmt.Errorf("failed to insert the OCSP record"))
	}

	if numRowsAffected != 1 {
		return wrapCertStoreError(fmt.Errorf("%d rows are affected, should be 1 row", numRowsAffected))
	}

	return err
}

// GetOCSP retrieves a OCSPRecord from db by serial.
func GetOCSP(db *sqlx.DB, serial string) (rr *OCSPRecord, err error) {
	rr = &OCSPRecord{}
	err = db.Get(rr, fmt.Sprintf(db.Rebind(selectOCSPSQL), sqlstruct.Columns(*rr)), serial)
	if err != nil {
		return nil, wrapCertStoreError(err)
	}

	return rr, nil
}

// GetUnexpiredOCSPs retrieves all unexpired OCSPRecord from db.
func GetUnexpiredOCSPs(db *sqlx.DB) (rrs []OCSPRecord, err error) {
	rrs = []OCSPRecord{}
	err = db.Select(&rrs, fmt.Sprintf(db.Rebind(selectAllUnexpiredOCSPSQL), sqlstruct.Columns(OCSPRecord{})))
	if err != nil {
		return nil, wrapCertStoreError(err)
	}

	return rrs, nil
}

// UpdateOCSP updates a ocsp response record with a given serial number.
func UpdateOCSP(db *sqlx.DB, serial, body string, expiry time.Time) (err error) {
	result, err := db.NamedExec(updateOCSPSQL, &OCSPRecord{
		Serial: serial,
		Body:   body,
		Expiry: expiry.UTC(),
	})

	if err != nil {
		return wrapCertStoreError(err)
	}

	numRowsAffected, err := result.RowsAffected()

	if numRowsAffected == 0 {
		return cferr.Wrap(cferr.CertStoreError, cferr.RecordNotFound, fmt.Errorf("failed to update the OCSP record"))
	}

	if numRowsAffected != 1 {
		return wrapCertStoreError(fmt.Errorf("%d rows are affected, should be 1 row", numRowsAffected))
	}

	return err
}

// UpsertOCSP update a ocsp response record with a given serial number,
// or insert the record if it doesn't yet exist in the db
// Implementation note:
// We didn't implement 'upsert' with SQL statement and we lost race condition
// prevention provided by underlying DMBS.
// Reasoning:
// 1. it's diffcult to support multiple DBMS backends in the same time, the
// SQL syntax differs from one to another.
// 2. we don't need a strict simultaneous consistency between OCSP and certificate
// status. It's OK that a OCSP response still shows 'good' while the
// corresponding certificate is being revoked seconds ago, as long as the OCSP
// response catches up to be eventually consistent (within hours to days).
// Write race condition between OCSP writers on OCSP table is not a problem,
// since we don't have write race condition on Certificate table and OCSP
// writers should periodically use Certificate table to update OCSP table
// to catch up.
func UpsertOCSP(db *sqlx.DB, serial, body string, expiry time.Time) (err error) {
	result, err := db.NamedExec(updateOCSPSQL, &OCSPRecord{
		Serial: serial,
		Body:   body,
		Expiry: expiry.UTC(),
	})

	if err != nil {
		return wrapCertStoreError(err)
	}

	numRowsAffected, err := result.RowsAffected()

	if numRowsAffected == 0 {
		return InsertOCSP(db, &OCSPRecord{Serial: serial, Body: body, Expiry: expiry})
	}

	if numRowsAffected != 1 {
		return wrapCertStoreError(fmt.Errorf("%d rows are affected, should be 1 row", numRowsAffected))
	}

	return err
}
