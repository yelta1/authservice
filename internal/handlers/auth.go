package handlers

import (	
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
	"sync"

	"authservice/internal/models"
)

type LoginAttempt struct {
    count       int
    blockedTill time.Time
}

var loginAttempts = make(map[string]*LoginAttempt)
var attemptsMu sync.Mutex

// POST /api/login
func (h *Handler) ApiLoginHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        sendError(w, http.StatusMethodNotAllowed, "Method not allowed")
        return
    }

    var req struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        sendError(w, http.StatusBadRequest, "Неверный формат запроса")
        return
    }

    if req.Username == "" || req.Password == "" {
        sendError(w, http.StatusBadRequest, "Логин и пароль обязательны")
        return
    }

    if !strings.HasPrefix(strings.ToLower(req.Username), "user") {
        sendError(w, http.StatusBadRequest, "Логин должен быть userXXXXX")
        return
    }

    req.Username = strings.ToLower(req.Username)

    key := req.Username

    attemptsMu.Lock()
    att, ok := loginAttempts[key]
    if !ok {
        att = &LoginAttempt{}
        loginAttempts[key] = att
    }

    if time.Now().Before(att.blockedTill) {
        attemptsMu.Unlock()
        sendError(w, http.StatusTooManyRequests, "Слишком много попыток. Попробуйте позже.")
        return
    }
    attemptsMu.Unlock()

	adUser, err := h.Auth.LdapAuthenticate(req.Username, req.Password)
	//adUser, err := auth.MockAuthenticate(req.Username, req.Password, true)
    if err != nil {

        attemptsMu.Lock()
        att := loginAttempts[key]
        att.count++

        if att.count >= 3 {
            att.blockedTill = time.Now().Add(10 * time.Minute)
            att.count = 0

            h.WriteLog("WARN", "Пользователь заблокирован после 3 попыток: "+req.Username, "auth_module")
        } else {
            if att.count == 1 {
                h.WriteLog("WARN", "Неудачная попытка входа: "+req.Username, "auth_module")
            }
        }

        attemptsMu.Unlock()

        sendError(w, http.StatusBadRequest, err.Error())
        return
    }

    attemptsMu.Lock()
    delete(loginAttempts, key)
    attemptsMu.Unlock()

    var userID int
    var role string
    var isActive bool
    var max_sessions int
    var role_id int

    err = h.Repo.DB.QueryRow(`
        SELECT id, role, is_active, max_sessions, role_id
        FROM users
        WHERE username=$1
    `, adUser.Username).Scan(&userID, &role, &isActive, &max_sessions, &role_id)

    if err == sql.ErrNoRows {
        err = h.Repo.DB.QueryRow(`
            INSERT INTO users
            (username, role, full_name, department, position, is_active, created_at, updated_at, max_sessions)
            VALUES ($1, 'viewer', $2, $3, $4, true, NOW(), NOW(), 2)
            RETURNING id
        `,
            adUser.Username,
            adUser.FullName,
            adUser.Department,
            adUser.Position,
        ).Scan(&userID)

        if err != nil {
            sendError(w, http.StatusInternalServerError, "Ошибка создания пользователя")
            log.Println(err)
            return
        }

        sendError(w, http.StatusInternalServerError, "Пользователь создан, нажминте кнопку Войти")
        return
    } else if err != nil {
        sendError(w, http.StatusInternalServerError, "Ошибка базы данных")
        return
    } else {
        if !isActive {
            sendError(w, http.StatusForbidden, "Пользователь заблокирован")
            return
        }

        _, _ = h.Repo.DB.Exec(`
            UPDATE users
            SET full_name=$1,
            department=$2,
            position=$3,
            updated_at=NOW()
            WHERE id=$4
        `,
            adUser.FullName,
            adUser.Department,
            adUser.Position,
            userID,
        )
    }

    h.WriteLog("INFO", "Пользователь "+adUser.Username+" успешно авторизован", "auth_module")

    sessionID := generateSessionID()
    _, err = h.Repo.DB.Exec(`
        INSERT INTO user_sessions
        (session_id, user_id, user_agent, ip_address, expires_at)
        VALUES ($1, $2, $3, $4, $5)
    `,
        sessionID,
        userID,
        r.UserAgent(),
        getIP(r),
        time.Now().Add(9*time.Hour),
    )

    if err != nil {
        sendError(w, http.StatusInternalServerError, "Ошибка создания сессии")
        return
    }

    var active_sessions int
    err = h.Repo.DB.QueryRow(`
        SELECT count(id)
        FROM user_sessions
        WHERE user_id=$1
        AND expires_at > now()
    `, userID).Scan(&active_sessions)

    if active_sessions > max_sessions {
        sendError(w, http.StatusInternalServerError, "Пользовтаель уже работает на другой инстанции")
        return
    }

    http.SetCookie(w, &http.Cookie{
        Name:     "session",
        Value:    sessionID,
        Path:     "/",
        HttpOnly: true,
        Secure:   false,
        SameSite: http.SameSiteStrictMode,
        MaxAge:   32400,
    })

    sendSuccess(w, models.User{
        ID:       userID,
        Username: adUser.Username,
        Name:     adUser.FullName,
        Role:     role,
    })
}

// GET /api/user
func (h *Handler) ApiUserHandler(w http.ResponseWriter, r *http.Request) {
	user, err := h.getCurrentUser(r)
	if err != nil {
		sendError(w, http.StatusUnauthorized, "Не авторизован")
		return
	}
	sendSuccess(w, user)
}

// GET /api/user-sessions - api для управление пользователями 
func (h *Handler) ApiUserSessionsHandler(w http.ResponseWriter, r *http.Request) {
    rows, err := h.Repo.DB.Query(`
        SELECT
            u.id,
            u.username,
            u.role,
            s.id,
            s.expires_at
        FROM users AS u
        LEFT JOIN user_sessions AS s
            ON u.id = s.user_id
            AND s.expires_at > NOW()
        ORDER BY u.id, s.id;
    `)
    if err != nil {
        sendError(w, http.StatusInternalServerError, "Ошибка запроса к БД")
        return
    }
    defer rows.Close()

    type Session struct {
        ID        int        `json:"id"`
        ExpiresAt *time.Time `json:"expires_at,omitempty"`
    }

    type User struct {
        ID       int       `json:"id"`
        Username string    `json:"username"`
        Role     string    `json:"role"`
        Sessions []Session `json:"sessions"`
    }

    usersMap := make(map[int]*User)

    for rows.Next() {
        var (
            userID    int
            username  string
            role      string
            sessID    *int
            expiresAt *time.Time
        )

        err := rows.Scan(&userID, &username, &role, &sessID, &expiresAt)
        if err != nil {
            sendError(w, http.StatusInternalServerError, "Ошибка чтения строк")
            return
        }

        // если пользователя ещё нет — добавляем
        if _, ok := usersMap[userID]; !ok {
            usersMap[userID] = &User{
                ID:       userID,
                Username: username,
                Role:     role,
                Sessions: []Session{},
            }
        }

        // если у пользователя есть активная сессия — добавляем её
        if sessID != nil {
            usersMap[userID].Sessions = append(
                usersMap[userID].Sessions,
                Session{ID: *sessID, ExpiresAt: expiresAt},
            )
        }
    }

    // преобразуем map → slice
    var users []User
    for _, u := range usersMap {
        users = append(users, *u)
    }

    sendSuccess(w, users)
}

func (h *Handler) ApiDeleteUserSessionByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 5 {
		sendError(w, http.StatusBadRequest, "Неверный формат запроса")
		return
	}
	id, err := strconv.Atoi(pathParts[3])
	if err != nil {
		sendError(w, http.StatusBadRequest, "Неверный ID")
		return
	}

	res, err := h.Repo.DB.Exec(`DELETE FROM user_sessions WHERE id = $1`, id)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "Ошибка удаления")
		return
	}

	affected, _ := res.RowsAffected()
	if affected == 0 {
		sendError(w, http.StatusNotFound, "Сессия не найдена")
		return
	}

	sendSuccess(w, "Удалено")

}

func (h *Handler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil && cookie.Value != "" {
		h.Repo.DB.Exec(`DELETE FROM user_sessions WHERE session_id = $1`, cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1, // Удалить куку
	})
	http.Redirect(w, r, "/", http.StatusSeeOther) // 303
	return
}