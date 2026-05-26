package main

import (
    "context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

    _ "github.com/lib/pq"
    
    "authservice/internal/handlers"
	"authservice/internal/repository"
	"authservice/internal/auth"
)

var db *sql.DB
var h *handlers.Handler

// ===== Configuration =====
type Config struct {
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
	DBSSLMode  string
	ServerPort string

	//LDAP
	LDAPServer        string
	LDAPBindDN        string
	LDAPBindPassword  string
	LDAPBaseDN        string
	LDAPRequiredGroup string
}

func loadConfig() *Config {
	return &Config{
		DBHost:     getEnv("DB_HOST", "localhost"),
		DBPort:     getEnv("DB_PORT", "5432"),
		DBUser:     getEnv("DB_USER", ""),
		DBPassword: getEnv("DB_PASSWORD", ""),
		DBName:     getEnv("DB_NAME", ""),
		DBSSLMode:  getEnv("DB_SSLMODE", "disable"),
		ServerPort: getEnv("SERVER_PORT", "8080"),

		LDAPServer:        getEnv("LDAP_SERVER", ""),
		LDAPBindDN:        getEnv("LDAP_BIND_DN", ""),
		LDAPBindPassword:  getEnv("LDAP_BIND_PASSWORD", ""),
		LDAPBaseDN:        getEnv("LDAP_BASE_DN", ""),
		LDAPRequiredGroup: getEnv("LDAP_REQUIRED_GROUP", ""),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc  { return h.AuthMiddleware(next) }
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc { return h.CorsMiddleware(next) }
func ManagerMiddleware(next http.HandlerFunc) http.HandlerFunc { return h.ManagerMiddleware(next) }
func AdminMiddleware(next http.HandlerFunc) http.HandlerFunc { return h.AdminMiddleware(next) }


func main() {
	// Загрузка конфигурации
	config := loadConfig()
	
	loc, _ := time.LoadLocation("Asia/Almaty")
    time.Local = loc
    
    // Подключение к БД
	var err error
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		config.DBHost, config.DBPort, config.DBUser, config.DBPassword, config.DBName, config.DBSSLMode)

	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Ошибка подключения к БД:", err)
	}
	defer db.Close()

	authService := auth.NewAuthService(auth.LDAPConfig{
		Server:        config.LDAPServer,
		BindDN:        config.LDAPBindDN,
		BindPassword:  config.LDAPBindPassword,
		BaseDN:        config.LDAPBaseDN,
		RequiredGroup: config.LDAPRequiredGroup,
	})

	// Настройки пула соединений
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err = db.Ping(); err != nil {
		log.Fatal("Ошибка ping БД:", err)
	}
	log.Println("Подключение к БД успешно")

	repo := repository.New(db)
    h = handlers.New(repo, authService)
    
    // Настройка маршрутов
	setupRoutes()

	// Настройка HTTP сервера
	srv := &http.Server{
		Addr:         ":" + config.ServerPort,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		log.Printf("Сервер запущен: http://localhost:%s", config.ServerPort)
		log.Printf("API доступен по адресу: http://localhost:%s/api", config.ServerPort)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Ошибка запуска сервера: %v", err)
		}
	}()

	// Ожидание сигнала остановки
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Остановка сервера...")

	// Graceful shutdown с таймаутом
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Ошибка при остановке сервера:", err)
	}
}