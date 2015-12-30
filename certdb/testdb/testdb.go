package testdb

import (
	"os"
	"path/filepath"
	"runtime"

	"bitbucket.org/liamstask/goose/lib/goose"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"           // register postgresql driver
	_ "github.com/mattn/go-sqlite3" // register sqlite3 driver
)

// PostgreSQLDB returns a PostgreSQL db instance for certdb testing with an empty DB.
func PostgreSQLDB() *sqlx.DB {
	prepDB := sqlx.MustOpen("postgres", "dbname=postgres sslmode=disable")

	prepDB.MustExec("DROP DATABASE IF EXISTS certdb_test;")
	prepDB.MustExec("CREATE DATABASE certdb_test;")

	db := sqlx.MustOpen("postgres", "dbname=certdb_test sslmode=disable")

	Migrate(db)

	return db
}

// SQLiteDB returns a SQLite db instance for certdb testing with an empty DB.
func SQLiteDB() *sqlx.DB {
	return SQLiteDBAtPath(":memory:")
}

// SQLiteDBAtPath returns an on-disk SQLite db instance for certdb testing with
// an empty DB. Mostly useful for testing the CLI
func SQLiteDBAtPath(dbpath string) *sqlx.DB {
	if _, err := os.Stat(dbpath); err == nil {
		if err = os.Remove(dbpath); err != nil {
			panic(err)
		}
	}

	db := sqlx.MustOpen("sqlite3", dbpath)
	Migrate(db)

	return db
}

// Setup returns a DB for the given driver
func Setup(driver string) *sqlx.DB {
	switch driver {
	case "postgres":
		return PostgreSQLDB()
	case "sqlite":
		return SQLiteDB()
	default:
		panic("Unknown driver")
	}
}

// Migrate makes sure the given db is current on migrations
func Migrate(db *sqlx.DB) {
	dbconf := gooseDBConf(db)

	target, err := goose.GetMostRecentDBVersion(dbconf.MigrationsDir)
	if err != nil {
		panic(err)
	}

	err = goose.RunMigrationsOnDb(dbconf, dbconf.MigrationsDir, target, db.DB)
	if err != nil {
		panic(err)
	}
}

func gooseDBConf(db *sqlx.DB) *goose.DBConf {
	driver := goose.DBDriver{}

	var dir string
	switch db.DriverName() {
	case "postgres":
		dir = "pg"
		driver.Dialect = &goose.PostgresDialect{}
	case "sqlite3":
		dir = "sqlite"
		driver.Dialect = &goose.Sqlite3Dialect{}
	default:
		panic("Unknown driver")
	}

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("Unable to determine migrations directory")
	}

	migrationsDir := filepath.Join(filepath.Dir(file), "..", dir, "migrations")

	return &goose.DBConf{
		Driver:        driver,
		Env:           "test",
		MigrationsDir: migrationsDir,
	}
}
