//Package gencrl implements the gencrl command
package gencrl

import (
	"database/sql"
	"errors"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/crl"
)

var gencrlUsageText = `cfssl gencrl -- generate a new Certificate Revocation List
If -db-config is provided, it will pull the list of revoked certificates from there.
Otherwise, the text file with a list of serial numbers is required.

Usage of gencrl:
        cfssl gencrl -ca cert -ca-key key [-crl-expiry 24h][-db-config db-config] [SERALLIST]

Arguments:
        SERALLIST (OPTIONAL):    Text file with one serial number per line, use '-' for reading text from stdin

Flags:
`
var gencrlFlags = []string{"ca", "ca-key", "crl-expiry", "db-config"}

func gencrlMain(args []string, c cli.Config) (err error) {
	if c.DBConfigFile != "" && len(args) > 0 {
		return errors.New("Only provide either DB config file (with -db-config) or serial list")
	} else if c.DBConfigFile == "" && len(args) == 0 {
		return errors.New("Need to provide either DB config file (with -db-config) or serial list")
	} else if c.DBConfigFile == "" && len(args) > 1 {
		return errors.New("Provided too many arguments, only expected one")
	}

	if c.CAFile == "" {
		return errors.New("Need a CA certificate (provide one with -ca)")
	}

	if c.CAKeyFile == "" {
		return errors.New("Need a CA key (provide one with -ca-key)")
	}

	// Read in the CA + CA Key
	certFileBytes, err := cli.ReadStdin(c.CAFile)
	if err != nil {
		return err
	}

	keyBytes, err := cli.ReadStdin(c.CAKeyFile)
	if err != nil {
		return err
	}

	var req []byte // Holds the signed CRL

	if c.DBConfigFile == "" {
		serialList, _, err := cli.PopFirstArgument(args)
		if err != nil {
			return err
		}

		serialListBytes, err := cli.ReadStdin(serialList)
		if err != nil {
			return err
		}

		req, err = crl.NewCRLFromFile(serialListBytes, certFileBytes, keyBytes, c.CRLExpiry)
		if err != nil {
			return err
		}
	} else {
		// Load in the DB
		var db *sql.DB
		db, err = certdb.DBFromConfig(c.DBConfigFile)
		if err != nil {
			return err
		}

		req, err = crl.NewCRLFromDB(db, certFileBytes, keyBytes, c.CRLExpiry)
		if err != nil {
			return err
		}
	}

	cli.PrintCRL(req)

	return nil
}

// Command assembles the definition of Command 'gencrl'
var Command = &cli.Command{UsageText: gencrlUsageText, Flags: gencrlFlags, Main: gencrlMain}
