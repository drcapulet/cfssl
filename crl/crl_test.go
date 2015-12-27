package crl

import (
	"crypto/x509"
	"database/sql"
	"io/ioutil"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/testdb"
)

const (
	serverCertFile = "testdata/ca.pem"
	serverKeyFile  = "testdata/ca-key.pem"
	tryTwoCert     = "testdata/caTwo.pem"
	tryTwoKey      = "testdata/ca-keyTwo.pem"
	serialList     = "testdata/serialList"
)

func TestNewCRLFromFile(t *testing.T) {

	tryTwoKeyBytes, err := ioutil.ReadFile(tryTwoKey)
	if err != nil {
		t.Fatal(err)
	}

	tryTwoCertBytes, err := ioutil.ReadFile(tryTwoCert)
	if err != nil {
		t.Fatal(err)
	}

	serialListBytes, err := ioutil.ReadFile(serialList)
	if err != nil {
		t.Fatal(err)
	}

	crl, err := NewCRLFromFile(serialListBytes, tryTwoCertBytes, tryTwoKeyBytes, 0*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	certList, err := x509.ParseDERCRL(crl)
	if err != nil {
		t.Fatal(err)
	}

	numCerts := len(certList.TBSCertList.RevokedCertificates)
	expectedNum := 4
	if expectedNum != numCerts {
		t.Fatal("Wrong number of expired certificates")
	}
}

func TestNewCRLFromFileWithoutRevocations(t *testing.T) {
	tryTwoKeyBytes, err := ioutil.ReadFile(tryTwoKey)
	if err != nil {
		t.Fatal(err)
	}

	tryTwoCertBytes, err := ioutil.ReadFile(tryTwoCert)
	if err != nil {
		t.Fatal(err)
	}

	crl, err := NewCRLFromFile([]byte("\n \n"), tryTwoCertBytes, tryTwoKeyBytes, 0*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	certList, err := x509.ParseDERCRL(crl)
	if err != nil {
		t.Fatal(err)
	}

	numCerts := len(certList.TBSCertList.RevokedCertificates)
	expectedNum := 0
	if expectedNum != numCerts {
		t.Fatal("Wrong number of expired certificates")
	}
}

func TestNewCRLFromDB(t *testing.T) {
	tryTwoCertBytes, err := ioutil.ReadFile(tryTwoCert)
	if err != nil {
		t.Fatal(err)
	}

	tryTwoKeyBytes, err := ioutil.ReadFile(tryTwoKey)
	if err != nil {
		t.Fatal(err)
	}

	db, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	crl, err := NewCRLFromDB(db, tryTwoCertBytes, tryTwoKeyBytes, 0*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	certList, err := x509.ParseDERCRL(crl)
	if err != nil {
		t.Fatal(err)
	}

	numCerts := len(certList.TBSCertList.RevokedCertificates)
	expectedNum := 1
	if expectedNum != numCerts {
		t.Fatal("Wrong number of expired certificates")
	}

	if certList.TBSCertList.RevokedCertificates[0].SerialNumber.String() != "2" {
		t.Fatal("Wrong expired certificate")
	}
}

func prepDB() (db *sql.DB, err error) {
	db = testdb.SQLiteDB("../certdb/testdb/certstore_development.db")
	expirationTime := time.Now().AddDate(1, 0, 0)

	err = certdb.InsertCertificate(db, &certdb.CertificateRecord{
		Serial: "1",
		Expiry: expirationTime,
		PEM:    "unexpired cert",
	})
	if err != nil {
		return nil, err
	}

	err = certdb.InsertCertificate(db, &certdb.CertificateRecord{
		Serial: "2",
		Expiry: expirationTime,
		PEM:    "unexpired cert",
	})
	if err != nil {
		return nil, err
	}

	err = certdb.RevokeCertificate(db, "2", 0)
	if err != nil {
		return nil, err
	}

	return db, nil
}
