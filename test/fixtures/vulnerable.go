// Deliberately vulnerable Go fixture.
package main

import (
	"database/sql"
	"net/http"
	"os/exec"
)

// VULN: SQL Injection — concatenation into Query()
func getUser(db *sql.DB, r *http.Request) (*sql.Rows, error) {
	id := r.URL.Query().Get("id")
	return db.Query("SELECT * FROM users WHERE id = " + id)
}

// VULN: Command Injection — shell invocation with concatenated input
func ping(r *http.Request) error {
	host := r.FormValue("host")
	return exec.Command("sh", "-c", "ping -c 1 "+host).Run()
}
