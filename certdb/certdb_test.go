package certdb

import (
	"math"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/certdb/testdb"

	"github.com/jmoiron/sqlx"
)

func TestSQLite(t *testing.T) {
	testEverything("sqlite", t)
}

// roughlySameTime decides if t1 and t2 are close enough.
func roughlySameTime(t1, t2 time.Time) bool {
	// return true if the difference is smaller than 1 sec.
	return math.Abs(float64(t1.Sub(t2))) < float64(time.Second)
}

func testEverything(driver string, t *testing.T) {
	testInsertCertificateAndGetCertificate(driver, t)
	testInsertCertificateAndGetUnexpiredCertificate(driver, t)
	testUpdateCertificateAndGetCertificate(driver, t)
	testInsertOCSPAndGetOCSP(driver, t)
	testInsertOCSPAndGetUnexpiredOCSP(driver, t)
	testUpdateOCSPAndGetOCSP(driver, t)
	testUpsertOCSPAndGetOCSP(driver, t)
}

func testInsertCertificateAndGetCertificate(driver string, t *testing.T) {
	db := testdb.Setup(driver)
	defer db.Close()

	expiry := time.Date(2010, time.December, 25, 23, 0, 0, 0, time.UTC)
	want := &CertificateRecord{
		PEM:     "fake cert data",
		Serial:  "fake serial",
		CALabel: "default",
		Status:  "good",
		Reason:  0,
		Expiry:  expiry,
	}

	if err := InsertCertificate(db, want); err != nil {
		t.Fatal(err)
	}

	got, err := GetCertificate(db, want.Serial)
	if err != nil {
		t.Fatal(err)
	}

	// relfection comparison with zero time objects are not stable as it seems
	if want.Serial != got.Serial || want.Status != got.Status ||
		want.CALabel != got.CALabel || !got.RevokedAt.IsZero() ||
		want.PEM != got.PEM || !roughlySameTime(got.Expiry, expiry) {
		t.Errorf("want Certificate %+v, got %+v", *want, *got)
	}

	unexpired, err := GetUnexpiredCertificates(db)

	if err != nil {
		t.Fatal(err)
	}

	if len(unexpired) != 0 {
		t.Error("should not have unexpired certificate record")
	}
}

func testInsertCertificateAndGetUnexpiredCertificate(driver string, t *testing.T) {
	db := testdb.Setup(driver)
	defer db.Close()

	expiry := time.Now().Add(time.Minute)
	want := &CertificateRecord{
		PEM:     "fake cert data",
		Serial:  "fake serial 2",
		CALabel: "default",
		Status:  "good",
		Reason:  0,
		Expiry:  expiry,
	}

	if err := InsertCertificate(db, want); err != nil {
		t.Fatal(err)
	}

	got, err := GetCertificate(db, want.Serial)
	if err != nil {
		t.Fatal(err)
	}

	// relfection comparison with zero time objects are not stable as it seems
	if want.Serial != got.Serial || want.Status != got.Status ||
		want.CALabel != got.CALabel || !got.RevokedAt.IsZero() ||
		want.PEM != got.PEM || !roughlySameTime(got.Expiry, expiry) {
		t.Errorf("want Certificate %+v, got %+v", *want, *got)
	}

	unexpired, err := GetUnexpiredCertificates(db)

	if err != nil {
		t.Fatal(err)
	}

	if len(unexpired) != 1 {
		t.Error("Should have 1 unexpired certificate record:", len(unexpired))
	}
}

func testUpdateCertificateAndGetCertificate(driver string, t *testing.T) {
	db := testdb.Setup(driver)
	defer db.Close()

	expiry := time.Date(2010, time.December, 25, 23, 0, 0, 0, time.UTC)
	want := &CertificateRecord{
		PEM:     "fake cert data",
		Serial:  "fake serial 3",
		CALabel: "default",
		Status:  "good",
		Reason:  0,
		Expiry:  expiry,
	}

	// Make sure the revoke on a non-existent cert
	if err := RevokeCertificate(db, want.Serial, 2); err == nil {
		t.Fatal("Expected error")
	}

	if err := InsertCertificate(db, want); err != nil {
		t.Fatal(err)
	}

	// reason 2 is CACompromise
	if err := RevokeCertificate(db, want.Serial, 2); err != nil {
		t.Fatal(err)
	}

	got, err := GetCertificate(db, want.Serial)
	if err != nil {
		t.Fatal(err)
	}

	// relfection comparison with zero time objects are not stable as it seems
	if want.Serial != got.Serial || got.Status != "revoked" ||
		want.CALabel != got.CALabel || got.RevokedAt.IsZero() ||
		want.PEM != got.PEM {
		t.Errorf("want Certificate %+v, got %+v", *want, *got)
	}
}

func testInsertOCSPAndGetOCSP(driver string, t *testing.T) {
	db := testdb.Setup(driver)
	defer db.Close()

	expiry := time.Date(2010, time.December, 25, 23, 0, 0, 0, time.UTC)
	want := &OCSPRecord{
		Serial: "fake serial",
		Body:   "fake body",
		Expiry: expiry,
	}
	setupGoodCert(db, t, want)

	if err := InsertOCSP(db, want); err != nil {
		t.Fatal(err)
	}

	got, err := GetOCSP(db, want.Serial)
	if err != nil {
		t.Fatal(err)
	}

	if want.Serial != got.Serial || want.Body != got.Body ||
		!roughlySameTime(want.Expiry, got.Expiry) {
		t.Errorf("want OCSP %+v, got %+v", *want, *got)
	}

	unexpired, err := GetUnexpiredOCSPs(db)

	if err != nil {
		t.Fatal(err)
	}

	if len(unexpired) != 0 {
		t.Error("should not have unexpired certificate record")
	}
}

func testInsertOCSPAndGetUnexpiredOCSP(driver string, t *testing.T) {
	db := testdb.Setup(driver)
	defer db.Close()

	want := &OCSPRecord{
		Serial: "fake serial 2",
		Body:   "fake body",
		Expiry: time.Now().Add(time.Minute),
	}
	setupGoodCert(db, t, want)

	if err := InsertOCSP(db, want); err != nil {
		t.Fatal(err)
	}

	got, err := GetOCSP(db, want.Serial)
	if err != nil {
		t.Fatal(err)
	}

	if want.Serial != got.Serial || want.Body != got.Body ||
		!roughlySameTime(want.Expiry, got.Expiry) {
		t.Errorf("want OCSP %+v, got %+v", *want, *got)
	}

	unexpired, err := GetUnexpiredOCSPs(db)

	if err != nil {
		t.Fatal(err)
	}

	if len(unexpired) != 1 {
		t.Error("should not have other than 1 unexpired certificate record:", len(unexpired))
	}
}

func testUpdateOCSPAndGetOCSP(driver string, t *testing.T) {
	db := testdb.Setup(driver)
	defer db.Close()

	want := &OCSPRecord{
		Serial: "fake serial 3",
		Body:   "fake body",
		Expiry: time.Date(2010, time.December, 25, 23, 0, 0, 0, time.UTC),
	}
	setupGoodCert(db, t, want)

	// Make sure the update fails
	if err := UpdateOCSP(db, want.Serial, want.Body, want.Expiry); err == nil {
		t.Fatal("Expected error")
	}

	if err := InsertOCSP(db, want); err != nil {
		t.Fatal(err)
	}

	newExpiry := time.Now().Add(time.Hour)
	if err := UpdateOCSP(db, want.Serial, "fake body revoked", newExpiry); err != nil {
		t.Fatal(err)
	}

	got, err := GetOCSP(db, want.Serial)
	if err != nil {
		t.Fatal(err)
	}

	want.Expiry = newExpiry
	if want.Serial != got.Serial || got.Body != "fake body revoked" ||
		!roughlySameTime(newExpiry, got.Expiry) {
		t.Errorf("want OCSP %+v, got %+v", *want, *got)
	}
}

func testUpsertOCSPAndGetOCSP(driver string, t *testing.T) {
	db := testdb.Setup(driver)
	defer db.Close()

	want := &OCSPRecord{
		Serial: "fake serial 3",
		Body:   "fake body",
		Expiry: time.Date(2010, time.December, 25, 23, 0, 0, 0, time.UTC),
	}
	setupGoodCert(db, t, want)

	if err := UpsertOCSP(db, want.Serial, want.Body, want.Expiry); err != nil {
		t.Fatal(err)
	}

	got, err := GetOCSP(db, want.Serial)
	if err != nil {
		t.Fatal(err)
	}

	if want.Serial != got.Serial || want.Body != got.Body ||
		!roughlySameTime(want.Expiry, got.Expiry) {
		t.Errorf("want OCSP %+v, got %+v", *want, *got)
	}

	newExpiry := time.Now().Add(time.Hour)
	if err := UpsertOCSP(db, want.Serial, "fake body revoked", newExpiry); err != nil {
		t.Fatal(err)
	}

	got, err = GetOCSP(db, want.Serial)
	if err != nil {
		t.Fatal(err)
	}

	want.Expiry = newExpiry
	if want.Serial != got.Serial || got.Body != "fake body revoked" ||
		!roughlySameTime(newExpiry, got.Expiry) {
		t.Errorf("want OCSP %+v, got %+v", *want, *got)
	}
}

func setupGoodCert(db *sqlx.DB, t *testing.T, r *OCSPRecord) {
	certWant := &CertificateRecord{
		PEM:     "fake cert data",
		Serial:  r.Serial,
		CALabel: "default",
		Status:  "good",
		Reason:  0,
		Expiry:  time.Now().Add(time.Minute),
	}

	if err := InsertCertificate(db, certWant); err != nil {
		t.Fatal(err)
	}
}
