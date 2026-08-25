package recondash

import (
	"encoding/json"
	"fmt"
	rv1db "go-recon/database_create" // Alias adicionado para bater com as structs
	"net/http"
	"path/filepath"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const IP_PERMITIDO = "127.0.0.1"

type App struct {
	DB *gorm.DB
}

func (a *App) firewallMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

func (a *App) apiHandler(w http.ResponseWriter, r *http.Request) {
	tabela := r.URL.Query().Get("tabela")
	busca := r.URL.Query().Get("search")

	w.Header().Set("Content-Type", "application/json")

	var resultados interface{}
	queryBusca := "%" + busca + "%"

	switch tabela {
	case "subdominios":
		var dados []rv1db.Subdominio
		a.DB.Where("host LIKE ?", queryBusca).Find(&dados)
		resultados = dados
	case "tecnologias":
		var dados []rv1db.Tecnologia
		a.DB.Where("subdominio LIKE ? OR tecnologias LIKE ?", queryBusca, queryBusca).Find(&dados)
		resultados = dados
	case "status":
		var dados []rv1db.Status
		a.DB.Where("subdominio LIKE ? OR status_code LIKE ?", queryBusca, queryBusca).Find(&dados)
		resultados = dados
	case "vetores":
		var dados []rv1db.Vetor
		a.DB.Where("url LIKE ? OR tipo LIKE ?", queryBusca, queryBusca).Find(&dados)
		resultados = dados
	default:
		http.Error(w, "Tabela inválida", http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(resultados)
}

func IniciarDashboard(empresa string, porta string) {
	fmt.Printf("\n[+] Iniciando Web Dashboard na porta %s...\n", porta)

	dbPath := filepath.Join(empresa, empresa+".db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		fmt.Printf("[-] Erro ao carregar o banco para o Dashboard: %v\n", err)
		return
	}

	app := &App{DB: db}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/dados", app.apiHandler)
	fs := http.FileServer(http.Dir("./recon-dash/static"))
	mux.Handle("/", fs)

	handlerSeguro := app.firewallMiddleware(mux)
	fmt.Printf("[+] Dashboard seguro rodando. Acesse via SSH: http://%s:%s\n", IP_PERMITIDO, porta)
	if err := http.ListenAndServe("0.0.0.0:"+porta, handlerSeguro); err != nil {
		fmt.Printf("[-] Erro no servidor: %v\n", err)
	}
}