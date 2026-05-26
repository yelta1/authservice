package main

import (
	"net/http"
	"strings"

	_ "github.com/lib/pq"
)

func setupRoutes() {

	// API endpoints
	http.HandleFunc("/api/logout", logoutHandler)
	http.HandleFunc("/api/login", corsMiddleware(apiLoginHandler))
	http.HandleFunc("/api/user", corsMiddleware(authMiddleware(apiUserHandler)))

	http.HandleFunc("/api/user-sessions", corsMiddleware(authMiddleware(ManagerMiddleware(apiGetUserUsessions))))
	http.HandleFunc("/api/user-sessions/", corsMiddleware(authMiddleware(ManagerMiddleware(func(w http.ResponseWriter, r *http.Request) {
		pathParts := strings.Split(r.URL.Path, "/")
		if len(pathParts) >= 5 {
			if pathParts[4] == "delete" {
				apiDeleteUserUsessions(w, r)
				return
			}
		}
		if r.Method == http.MethodGet {
			apiGetUserUsessions(w, r)
		}
	}))))

	http.HandleFunc("/api/roles", corsMiddleware(authMiddleware(AdminMiddleware(apiRolesHandler))))
}