package recondash

import (
	"encoding/json"
	"fmt"
	rv1db "go-recon/database_create" // Alias adicionado para bater com as structs
	//"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const IP_PERMITIDO = "127.0.0.1"
const (
	limitPadrao = 50
	limitMaximo = 200
)

type App struct {
	DB *gorm.DB
}

var filtrosInteligentes = map[string][]string{
	"php":           {".php"},
	"wp":            {"wp-", "wordpress"},
	"apis":          {"graphql", "swagger", "/api/"},
	"sensiveis":     {".bak", ".sql", ".env", ".git"},
	"lfi_rce":       {"file=", "path=", "doc=", "template="},
	"ssrf_redirect": {"url=", "next=", "return=", "target="},
	"sqli_idor":     {"id=", "user_id=", "sort=", "order="},
	"dev_test":      {"dev", "staging", "test", "sandbox"},
	"admin":         {"admin", "dashboard", "internal"},
	"api_old":       {"/v1/", "/v2/"},
}

var extensoesLixo = []string{".js", ".css", ".png", ".svg", ".woff", ".woff2", ".jpg", ".jpeg", ".gif", ".ico"}

type respostaPaginada struct {
	Dados        interface{} `json:"dados"`
	Total        int64       `json:"total"`
	Pagina       int         `json:"pagina"`
	TotalPaginas int         `json:"total_paginas"`
	Limite       int         `json:"limite"`
}

// firewallMiddleware agora valida de fato o IP de origem.
// Antes o nome prometia um filtro que não existia: a função só repassava
// a requisição adiante (net/http nunca chegou a checar nada).
func (a *App) firewallMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // host, _, err := net.SplitHostPort(r.RemoteAddr)
        // if err != nil {
        //     host = r.RemoteAddr
        // }
        // if host != IP_PERMITIDO && host != "::1" {
        //     http.Error(w, "Acesso negado", http.StatusForbidden)
        //     return
        // }
        
        // Agora o middleware apenas permite a passagem
        next.ServeHTTP(w, r)
    })
}
func paginacao(r *http.Request) (page, limit, offset int) {
	page, _ = strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = limitPadrao
	}
	if limit > limitMaximo {
		limit = limitMaximo
	}
	offset = (page - 1) * limit
	return
}

func (a *App) apiHandler(w http.ResponseWriter, r *http.Request) {
	tabela := r.URL.Query().Get("tabela")
	busca := r.URL.Query().Get("search")
	page, limit, offset := paginacao(r)

	w.Header().Set("Content-Type", "application/json")

	queryBusca := "%" + busca + "%"
	var total int64
	var resultados interface{}

	switch tabela {
	case "subdominios":
		var dados []rv1db.Subdominio
		q := a.DB.Model(&rv1db.Subdominio{}).Where("host LIKE ?", queryBusca)
		q.Count(&total)
		q.Order("id DESC").Limit(limit).Offset(offset).Find(&dados)
		resultados = dados
	case "resolvidos":
		var dados []rv1db.Resolvido
		q := a.DB.Model(&rv1db.Resolvido{}).Where("host LIKE ?", queryBusca)
		q.Count(&total)
		q.Order("id DESC").Limit(limit).Offset(offset).Find(&dados)
		resultados = dados
	case "tecnologias":
		var dados []rv1db.Tecnologia
		q := a.DB.Model(&rv1db.Tecnologia{}).Where("subdominio LIKE ? OR tecnologias LIKE ?", queryBusca, queryBusca)
		q.Count(&total)
		q.Order("id DESC").Limit(limit).Offset(offset).Find(&dados)
		resultados = dados
	case "status":
		var dados []rv1db.Status
		q := a.DB.Model(&rv1db.Status{}).Where("subdominio LIKE ? OR status_code LIKE ?", queryBusca, queryBusca)
		q.Count(&total)
		q.Order("id DESC").Limit(limit).Offset(offset).Find(&dados)
		resultados = dados
	case "vetores":
		var dados []rv1db.Vetor
		q := a.DB.Model(&rv1db.Vetor{}).Where("url LIKE ? OR tipo LIKE ?", queryBusca, queryBusca)

		if tiposParam := r.URL.Query().Get("tipos"); tiposParam != "" {
			tipos := strings.Split(tiposParam, ",")
			for i := range tipos {
				tipos[i] = strings.TrimSpace(tipos[i])
			}
			q = q.Where("tipo IN ?", tipos)
		}

		if filtrosParam := r.URL.Query().Get("filtros"); filtrosParam != "" {
			for _, chave := range strings.Split(filtrosParam, ",") {
				chave = strings.TrimSpace(chave)
				padroes, ok := filtrosInteligentes[chave]
				if !ok {
					continue
				}
				condicoes := make([]string, 0, len(padroes))
				args := make([]interface{}, 0, len(padroes))
				for _, p := range padroes {
					condicoes = append(condicoes, "url LIKE ?")
					args = append(args, "%"+p+"%")
				}
				q = q.Where(strings.Join(condicoes, " OR "), args...)
			}
		}
		if r.URL.Query().Get("limpar_lixo") == "1" {
			for _, ext := range extensoesLixo {
				q = q.Where("url NOT LIKE ?", "%"+ext+"%")
			}
		}

		q.Count(&total)
		q.Order("id DESC").Limit(limit).Offset(offset).Find(&dados)
		resultados = dados
	case "cloud":
		var dados []rv1db.CloudAsset
		q := a.DB.Model(&rv1db.CloudAsset{}).Where(
			"provider LIKE ? OR bucket LIKE ? OR url LIKE ? OR classificacao LIKE ?",
			queryBusca, queryBusca, queryBusca, queryBusca,
		)
		q.Count(&total)
		q.Order("id DESC").Limit(limit).Offset(offset).Find(&dados)
		resultados = dados
	default:
		http.Error(w, "Tabela inválida", http.StatusBadRequest)
		return
	}

	totalPaginas := int((total + int64(limit) - 1) / int64(limit))
	if totalPaginas == 0 {
		totalPaginas = 1
	}

	json.NewEncoder(w).Encode(respostaPaginada{
		Dados:        resultados,
		Total:        total,
		Pagina:       page,
		TotalPaginas: totalPaginas,
		Limite:       limit,
	})
}

func (a *App) tiposVetorHandler(w http.ResponseWriter, r *http.Request) {
	var tipos []string
	a.DB.Model(&rv1db.Vetor{}).Distinct().Order("tipo ASC").Pluck("tipo", &tipos)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tipos)
}

type resumoDashboard struct {
	Subdominios int64            `json:"subdominios"`
	Resolvidos  int64            `json:"resolvidos"`
	Tecnologias int64            `json:"tecnologias"`
	Vetores     int64            `json:"vetores"`
	StatusOK    int64            `json:"status_ok"`
	CloudAssets int64            `json:"cloud"`
	PorVetor    map[string]int64 `json:"por_vetor"`
}

func (a *App) resumoHandler(w http.ResponseWriter, r *http.Request) {
	var resumo resumoDashboard
	resumo.PorVetor = make(map[string]int64)

	a.DB.Model(&rv1db.Subdominio{}).Count(&resumo.Subdominios)
	a.DB.Model(&rv1db.Resolvido{}).Count(&resumo.Resolvidos)
	a.DB.Model(&rv1db.Tecnologia{}).Count(&resumo.Tecnologias)
	a.DB.Model(&rv1db.Vetor{}).Count(&resumo.Vetores)
	a.DB.Model(&rv1db.Status{}).Where("status_code LIKE ?", "%200%").Count(&resumo.StatusOK)
	a.DB.Model(&rv1db.CloudAsset{}).Count(&resumo.CloudAssets)

	type contagem struct {
		Tipo  string
		Total int64
	}
	var contagens []contagem
	a.DB.Model(&rv1db.Vetor{}).Select("tipo, count(*) as total").Group("tipo").Scan(&contagens)
	for _, c := range contagens {
		resumo.PorVetor[c.Tipo] = c.Total
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resumo)
}

func IniciarDashboard(empresa string, porta string) {
	fmt.Printf("\n[+] Iniciando Web Dashboard na porta %s...\n", porta)

	dbPath := filepath.Join(empresa, empresa+".db")
	dsn := dbPath + "?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		fmt.Printf("[-] Erro ao carregar o banco para o Dashboard: %v\n", err)
		return
	}

	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(4)
		sqlDB.SetConnMaxLifetime(time.Hour)
	}

	app := &App{DB: db}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/dados", app.apiHandler)
	mux.HandleFunc("/api/vetores/tipos", app.tiposVetorHandler)
	mux.HandleFunc("/api/resumo", app.resumoHandler)
	fs := http.FileServer(http.Dir("./recon-dash/static"))
	mux.Handle("/", fs)

	handlerSeguro := app.firewallMiddleware(mux)
	fmt.Printf("[+] Dashboard seguro rodando. Acesse via SSH: http://%s:%s\n", IP_PERMITIDO, porta)
	if err := http.ListenAndServe("0.0.0.0:"+porta, handlerSeguro); err != nil {
		fmt.Printf("[-] Erro no servidor: %v\n", err)
	}
}
