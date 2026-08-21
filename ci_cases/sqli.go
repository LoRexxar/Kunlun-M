package main

import (
    "database/sql"
    "net/http"
)

func handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query().Get("q")
    db.Query("SELECT * FROM users WHERE name='" + q + "'")
}
