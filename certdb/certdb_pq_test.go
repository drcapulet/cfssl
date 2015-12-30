// +build postgresql

package certdb

import "testing"

func TestPostgreSQL(t *testing.T) {
	testEverything("postgres", t)
}
