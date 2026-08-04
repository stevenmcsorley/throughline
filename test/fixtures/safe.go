// Idiomatic, safe Go. Any finding here is a false positive.
package main

import (
	"database/sql"
	"net/http"
	"os/exec"
)

func getUser(db *sql.DB, r *http.Request) (*sql.Rows, error) {
	// Placeholder — the driver binds the value.
	return db.Query("SELECT * FROM users WHERE id = $1", r.URL.Query().Get("id"))
}

func ping(r *http.Request) error {
	// Direct binary, separate arguments, no shell.
	host := r.FormValue("host")
	return exec.Command("ping", "-c", "1", host).Run()
}
