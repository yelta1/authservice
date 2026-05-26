package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

)

func (h *Handler) ApiRolesHandler(w http.ResponseWriter, r *http.Request) {
    rows, err := h.Repo.DB.Query(`SELECT name FROM user_roles ORDER BY id`)
    if err != nil {
        sendError(w, 500, "Ошибка получения списка ролей")
        return
    }
    defer rows.Close()

    var roles []string

    for rows.Next() {
        var role string
        if err := rows.Scan(&role); err != nil {
            sendError(w, 500, "Ошибка чтения данных ролей")
            return
        }
        roles = append(roles, role)
    }

    sendSuccess(w, roles)
}

func (h* Handler)ApiChangeUserRole(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        sendError(w, http.StatusMethodNotAllowed, "Method not allowed")
        return
    }

    pathParts := strings.Split(r.URL.Path, "/")
    // /api/users/:id/role → parts[3] = id
    if len(pathParts) < 5 {
        sendError(w, http.StatusBadRequest, "Неверный формат запроса")
        return
    }

    userID, err := strconv.Atoi(pathParts[3])
    if err != nil {
        sendError(w, http.StatusBadRequest, "Неверный ID")
        return
    }

    // Читаем JSON {"role": "manager"}
    var body struct {
        Role string `json:"role"`
    }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        sendError(w, http.StatusBadRequest, "Некорректный JSON")
        return
    }

    // Проверяем есть ли такая роль
    var roleID int
    err = h.Repo.DB.QueryRow(`SELECT id FROM user_roles WHERE name = $1`, body.Role).Scan(&roleID)

    if err == sql.ErrNoRows {
        sendError(w, 400, "Такой роли не существует")
        return
    }
    if err != nil {
        sendError(w, 500, "Ошибка проверки роли")
        return
    }

    // Обновляем пользователя
    _, err = h.Repo.DB.Exec(`
        UPDATE users
        SET role_id = $1, role = $2
        WHERE id = $3
    `, roleID, body.Role, userID)

    if err != nil {
        sendError(w, 500, "Ошибка обновления роли")
        return
    }

    sendSuccess(w, "Роль обновлена")
}