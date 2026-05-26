package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"authservice/internal/models"
	"authservice/internal/repository"
	"authservice/internal/auth"
)

type Handler struct {
	Repo *repository.Repository
	Auth *auth.AuthService
}

func New(repo *repository.Repository, authService *auth.AuthService) *Handler {
    return &Handler{
        Repo: repo,
        Auth: authService,
    }
}

// ===== Helper Functions =====
func generateSessionID() string {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		// Fallback: используем криптографически безопасный rand из crypto/rand
		// Не используем math/rand!
		fallback := make([]byte, 32)
		if _, err := rand.Read(fallback); err != nil {
			// Если совсем ничего не работает
			fallback = []byte(fmt.Sprintf("%d%d", time.Now().UnixNano(), time.Now().Unix()))
		}
		b = fallback
	}
	return base64.URLEncoding.EncodeToString(b)
}

func (h *Handler) getCurrentUser(r *http.Request) (*models.User, error) {
	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value == "" {
		return nil, fmt.Errorf("not authenticated")
	}
	var user models.User
	var role string
	var uagent string
	err = h.Repo.DB.QueryRow(`
        SELECT u.id, u.username, u.role, COALESCE(u.full_name, u.username) as name, s.user_agent
        FROM users u
        JOIN user_sessions s ON s.user_id = u.id
        WHERE s.session_id = $1
          AND s.expires_at > NOW()
          AND s.is_valid = true
          AND u.is_active = true
        LIMIT 1
    `, cookie.Value).Scan(&user.ID, &user.Username, &role, &user.Name, &uagent)
	if err != nil {
		if err == sql.ErrNoRows {
			// Невалидная сессия
			return nil, fmt.Errorf("invalid session")
		}
		log.Printf("Session query error: %v", err)
		return nil, err
	}

	if uagent != r.UserAgent() {
		return nil, fmt.Errorf("invalid session")
	}

	// Обновляем время последней активности
	h.Repo.DB.Exec(`UPDATE user_sessions SET last_activity = NOW() WHERE session_id = $1`, cookie.Value)
	user.Role = role
	return &user, nil
}

func sendJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}
func sendError(w http.ResponseWriter, statusCode int, message string) {
	sendJSON(w, statusCode, models.APIResponse{
		Success: false,
		Error:   message,
	})
}
func sendSuccess(w http.ResponseWriter, data interface{}) {
	sendJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Data:    data,
	})
}

func getIP(r *http.Request) string {
	
	// 1. CF-Connecting-IP (Cloudflare)
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}

	// 2. X-Forwarded-For (nginx / ingress)
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		parts := strings.Split(ip, ",")
		return strings.TrimSpace(parts[0]) // первый IP пользователя
	}

	// 3. X-Real-IP (nginx)
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}

	// 4. RemoteAddr (fallback)
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip

}

// ===== Middleware =====
func (h *Handler) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" || r.URL.Path == "/logout" {
			next(w, r)
			return
		}
		user, err := h.getCurrentUser(r)
		if err != nil {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				sendError(w, http.StatusUnauthorized, "Не авторизован")
				//clientIP := getIP(r)
				//h.WriteLog("WARN", "Попытка доступа без авторизации с IP: " + clientIP) //Пишет в общий лог
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if user.Role == "viewer" {
			http.Redirect(w, r, "/registration", http.StatusFound)
			return
		}
		next(w, r)
	}
}

func (h *Handler) ManagerMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := h.getCurrentUser(r)
		if err != nil {
			sendError(w, http.StatusUnauthorized, "Не авторизован")
			return
		}
		if user.Role != "admin" && user.Role != "manager" {
			sendError(w, http.StatusForbidden, "Доступ запрещен. Требуются права руководителя")
			return
		}
		next(w, r)
	}
}

func (h *Handler) AdminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := h.getCurrentUser(r)
		if err != nil {
			sendError(w, http.StatusUnauthorized, "Не авторизован")
			return
		}
		if user.Role != "admin" {
			sendError(w, http.StatusForbidden, "Доступ запрещен. Требуются права администратора")
			h.WriteLog("WARN", "Попытка доступа в админ-панель: ", user.Username) //Пишет в общий лог
			return
		}
		next(w, r)
	}
}

func (h *Handler) CorsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://10.49.44.83:3000")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}
