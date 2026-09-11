package main

// Real-world SQL injection test cases for Kunlun-M scanner
// Simulates a Go web application with user management and search features
// Expected detections: 3 TRUE POSITIVE (SQL injection), 1 SAFE

import (
	"database/sql"
	"fmt"
	"net/http"
)

// UserAPI simulates a user management service with a PostgreSQL backend
type UserAPI struct {
	db *sql.DB
}

// VULN-1: SQL injection via fmt.Sprintf in db.Query
// User-controlled "username" param concatenated directly into WHERE clause
func (api *UserAPI) LoginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	// VULN: string concatenation in SQL query — classic SQL injection
	query := fmt.Sprintf("SELECT id, username, role FROM users WHERE username='%s' AND password='%s'", username, password)
	row := api.db.QueryRow(query)
	var id int
	var user, role string
	err := row.Scan(&id, &user, &role)
	if err != nil {
		http.Error(w, "login failed", 401)
		return
	}
	fmt.Fprintf(w, "Welcome %s (role: %s)", user, role)
}

// VULN-2: SQL injection via fmt.Sprintf in db.Exec for UPDATE
// User-controlled "email" and "userId" params concatenated into UPDATE statement
func (api *UserAPI) UpdateEmailHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	userId := r.URL.Query().Get("userId")
	// VULN: both email and userId are user-controlled, concatenated into SQL
	query := fmt.Sprintf("UPDATE users SET email = '%s' WHERE id = %s", email, userId)
	_, err := api.db.Exec(query)
	if err != nil {
		http.Error(w, "update failed", 500)
		return
	}
	fmt.Fprintf(w, "Email updated successfully")
}

// VULN-3: SQL injection via fmt.Sprintf in db.Query for search
// User-controlled "keyword" param concatenated into LIKE clause
func (api *UserAPI) SearchUsersHandler(w http.ResponseWriter, r *http.Request) {
	keyword := r.URL.Query().Get("q")
	// VULN: keyword injected directly into LIKE clause
	query := fmt.Sprintf("SELECT id, username, email FROM users WHERE username LIKE '%%%s%%' OR email LIKE '%%%s%%'", keyword, keyword)
	rows, err := api.db.Query(query)
	if err != nil {
		http.Error(w, "search failed", 500)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var username, email string
		rows.Scan(&id, &username, &email)
		fmt.Fprintf(w, "%d: %s <%s>\n", id, username, email)
	}
}

// SAFE: Parameterized query using $1, $2 placeholders (PostgreSQL style)
// User input is passed as separate arguments, never concatenated into SQL
func (api *UserAPI) SafeGetUserHandler(w http.ResponseWriter, r *http.Request) {
	userId := r.URL.Query().Get("id")
	// SAFE: parameterized query with $1 placeholder
	row := api.db.QueryRow("SELECT id, username, email FROM users WHERE id = $1", userId)
	var id int
	var username, email string
	err := row.Scan(&id, &username, &email)
	if err != nil {
		http.Error(w, "user not found", 404)
		return
	}
	fmt.Fprintf(w, "%d: %s <%s>", id, username, email)
}

// SAFE: Parameterized query with multiple placeholders for INSERT
// User input is passed as separate arguments to db.Exec
func (api *UserAPI) SafeCreateUserHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	email := r.FormValue("email")
	role := r.FormValue("role")
	// SAFE: parameterized query with $1, $2, $3 placeholders
	_, err := api.db.Exec(
		"INSERT INTO users (username, email, role) VALUES ($1, $2, $3)",
		username, email, role,
	)
	if err != nil {
		http.Error(w, "create failed", 500)
		return
	}
	fmt.Fprintf(w, "User %s created", username)
}

func main() {
	db, _ := sql.Open("postgres", "postgres://user:pass@localhost/dbname?sslmode=disable")
	defer db.Close()
	api := &UserAPI{db: db}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", api.LoginHandler)
	mux.HandleFunc("/user/update-email", api.UpdateEmailHandler)
	mux.HandleFunc("/users/search", api.SearchUsersHandler)
	mux.HandleFunc("/user/get", api.SafeGetUserHandler)
	mux.HandleFunc("/user/create", api.SafeCreateUserHandler)
	fmt.Println("User API server running on :8081")
	http.ListenAndServe(":8081", mux)
}
