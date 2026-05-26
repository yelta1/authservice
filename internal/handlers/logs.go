package handlers

import (
    "log"
    "net/http"
	"strconv"
	"fmt"
	"strings"
	"time"

	"authservice/internal/models"
)

//Getter Log
func (h *Handler) GetLogsData(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query()

    // Пагинация
    page := 1
    if p := query.Get("page"); p != "" {
        if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
            page = parsed
        }
    }

    pageSize := 5
    if ps := query.Get("pageSize"); ps != "" {
        if parsed, err := strconv.Atoi(ps); err == nil && parsed >= 10 {
            pageSize = parsed
        }
    }

    // Фильтры
    level := query.Get("level")
    dateFrom := query.Get("dateFrom")
    dateTo := query.Get("dateTo")
    search := query.Get("search")

    // WHERE‑билдер
    where := []string{"1=1"}
    args := []interface{}{}
    argPos := 1

    if level != "" {
        where = append(where, fmt.Sprintf("l.level = $%d", argPos))
        args = append(args, level)
        argPos++
    }

    if dateFrom != "" {
        where = append(where, fmt.Sprintf("l.timestamp >= $%d", argPos))
        args = append(args, dateFrom)
        argPos++
    }

    if dateTo != "" {
        where = append(where, fmt.Sprintf("l.timestamp <= $%d", argPos))
        args = append(args, dateTo)
        argPos++
    }

    if search != "" {
        where = append(where, fmt.Sprintf("(l.message ILIKE $%d)", argPos))
        args = append(args, "%"+search+"%")
        argPos++
    }

    whereSQL := strings.Join(where, " AND ")

    // Подсчёт total
    var total int
    countQuery := fmt.Sprintf(`
        SELECT COUNT(*) 
        FROM logs l
        WHERE %s
    `, whereSQL)

    err := h.Repo.DB.QueryRow(countQuery, args...).Scan(&total)
    if err != nil {
        log.Printf("Error counting logs: %v", err)
        sendError(w, http.StatusInternalServerError, "Ошибка запроса к БД")
        return
    }

    totalPages := (total + pageSize - 1) / pageSize
    if totalPages < 1 {
        totalPages = 1
    }

    offset := (page - 1) * pageSize

    // Основной запрос
    mainArgs := make([]interface{}, len(args))
    copy(mainArgs, args)
    mainArgs = append(mainArgs, pageSize, offset)

    limitPos := len(args) + 1
    offsetPos := len(args) + 2

    querySQL := fmt.Sprintf(`
        SELECT 
            l.id,
            l.timestamp,
            l.level,
            l.message,
            l.username
        FROM logs l
        WHERE %s
        ORDER BY l.timestamp DESC
        LIMIT $%d OFFSET $%d
    `, whereSQL, limitPos, offsetPos)

    rows, err := h.Repo.DB.Query(querySQL, mainArgs...)
    if err != nil {
        log.Printf("Error querying logs: %v", err)
        sendError(w, http.StatusInternalServerError, "Ошибка запроса к БД")
        return
    }
    defer rows.Close()

    type LogItem struct {
        ID        int        `json:"id"`
        Timestamp string     `json:"timestamp"`
        Level     string     `json:"level"`
        Message   string     `json:"message"`
        Username string      `json:username`
    }

    var logs []LogItem

    for rows.Next() {
        var (
            id        int
            timestamp time.Time
            level     string
            message   string
            username  string
        )

        if err := rows.Scan(&id, &timestamp, &level, &message, &username); err != nil {
            log.Printf("Error scanning log row: %v", err)
            continue
        }

        logs = append(logs, LogItem{
            ID:        id,
            Timestamp: timestamp.Format("2006-01-02 15:04:05"),
            Level:     level,
            Message:   message,
            Username:   username,
        })
    }

    if rows.Err() != nil {
        log.Printf("Row iteration error: %v", rows.Err())
        sendError(w, http.StatusInternalServerError, "Ошибка обработки данных")
        return
    }

    if logs == nil {
        logs = []LogItem{}
    }

    sendSuccess(w, models.PaginatedResponse{
        Items:      logs,
        Total:      total,
        Page:       page,
        PageSize:   pageSize,
        TotalPages: totalPages,
    })
}
//Setter Log
func (h *Handler) WriteLog(level, message, username string) error {
    if level == "" {
        level = "INFO"
    }

    user := username

    query := `
        INSERT INTO logs (timestamp, level, message, username)
        VALUES ($1, $2, $3, $4)
    `

    _, err := h.Repo.DB.Exec(query, time.Now(), level, message, user)
    if err != nil {
        log.Printf("Error writing log: %v", err)
        return err
    }

    return nil
}