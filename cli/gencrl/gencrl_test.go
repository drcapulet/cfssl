package gencrl

import (
	"testing"

	"github.com/cloudflare/cfssl/cli"
)

func TestGencrlList(t *testing.T) {
	err := gencrlMain([]string{"testdata/serialList"}, cli.Config{
		CAFile:    "testdata/caTwo.pem",
		CAKeyFile: "testdata/ca-keyTwo.pem",
	})

	if err != nil {
		t.Fatal(err)
	}
}

func TestGencrlDBConfig(t *testing.T) {
	err := gencrlMain([]string{"testdata/serialList"}, cli.Config{
		CAFile:    "testdata/caTwo.pem",
		CAKeyFile: "testdata/ca-keyTwo.pem",
	})

	if err != nil {
		t.Fatal(err)
	}
}

func TestGencrlMissingSerialListAndDBConfig(t *testing.T) {
	err := gencrlMain([]string{}, cli.Config{})

	if err == nil {
		t.Fatal("Expected error but didn't get one")
	}
}

func TestGencrlProvidedBothDBConfigAndSerialList(t *testing.T) {
	err := gencrlMain([]string{"testdata/serialList"}, cli.Config{
		DBConfigFile: "testdata/db-config.json",
	})

	if err == nil {
		t.Fatal("Expected error but didn't get one")
	}
}

func TestGencrlTooManyArgs(t *testing.T) {
	err := gencrlMain([]string{"testdata/serialList", "testdata/serialList2"}, cli.Config{})

	if err == nil {
		t.Fatal("Expected error but didn't get one")
	}
}

func TestGencrlMissingCAFile(t *testing.T) {
	err := gencrlMain([]string{"testdata/serialList"}, cli.Config{
		CAFile:    "",
		CAKeyFile: "testdata/ca-keyTwo.pem",
	})

	if err == nil {
		t.Fatal("Expected error but didn't get one")
	}
}

func TestGencrlMissingCAKeyFile(t *testing.T) {
	err := gencrlMain([]string{"testdata/serialList"}, cli.Config{
		CAFile:    "testdata/caTwo.pem",
		CAKeyFile: "",
	})

	if err == nil {
		t.Fatal("Expected error but didn't get one")
	}
}
