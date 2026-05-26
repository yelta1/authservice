package main

import (
	"net/http"

	_ "github.com/lib/pq"
)
func logoutHandler(w http.ResponseWriter, r *http.Request) { h.LogoutHandler(w, r) }
func apiLoginHandler(w http.ResponseWriter, r *http.Request) { h.ApiLoginHandler(w, r) }
func apiUserHandler(w http.ResponseWriter, r *http.Request)  { h.ApiUserHandler(w, r) }
func apiGetUserUsessions(w http.ResponseWriter, r *http.Request){h.ApiUserSessionsHandler(w, r)}
func apiDeleteUserUsessions(w http.ResponseWriter, r *http.Request){h.ApiDeleteUserSessionByID(w, r)}

func apiRolesHandler(w http.ResponseWriter, r *http.Request){h.ApiRolesHandler(w, r)}
func apiChangeUserRole(w http.ResponseWriter, r *http.Request){h.ApiChangeUserRole(w, r)}

