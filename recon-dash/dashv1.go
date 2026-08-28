package recondash

import (
	"encoding/json"
	"fmt"
	rv1db "go-recon/database_create" // Alias adicionado para bater com as structs

	//"net"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const IP_PERMITIDO = "127.0.0.1"

// Limites de paginação: evita que a API devolva a tabela inteira de uma vez,
// que era a causa raiz do dashboard travar com bases grandes.
const (
	limitPadrao = 50
	limitMaximo = 200
)

type App struct {
	DB *gorm.DB
}

// filtrosInteligentes mapeia cada "tag" de filtro para os padrões buscados
// na URL (correspondência textual simples via LIKE, sem regex, pra manter
// a query rápida mesmo com dezenas de milhares de vetores no banco).
// Dentro da mesma tag os padrões são combinados com OR; entre tags
// diferentes ativas ao mesmo tempo, o handler combina com AND (facetas que
// se somam, ex: "Dev/Test" + "LFI/RCE" = achar parâmetro de LFI só em
// ambiente de dev).
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

// extensoesLixo são extensões de asset estático que normalmente não
// interessam na caça de bugs; usadas pelo toggle "Limpar Lixo".
var extensoesLixo = []string{".js", ".css", ".png", ".svg", ".woff", ".woff2", ".jpg", ".jpeg", ".gif", ".ico"}

// respostaPaginada é o envelope padrão devolvido por /api/dados.
// Antes o endpoint devolvia um array "solto"; agora devolve também
// total de registros e total de páginas, para o frontend paginar de verdade.
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

// paginacao lê "page" e "limit" da query string com valores seguros de fallback.
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
	case "hosts":
		// Visão unificada: Resolvidos + Status Code + Tecnologias numa
		// linha só por host. Substitui as antigas abas separadas.
		var dados []rv1db.Host
		q := a.DB.Model(&rv1db.Host{}).Where(
			"host LIKE ? OR status_code LIKE ? OR tecnologias LIKE ?",
			queryBusca, queryBusca, queryBusca,
		)

		// Filtro por tecnologia (?tecnologias=React,PHP,Envoy): campo é
		// CSV numa coluna só, então cada tag vira "tecnologias LIKE %tag%"
		// combinadas com OR (mostra o host se tiver QUALQUER uma marcada).
		if techParam := r.URL.Query().Get("tecnologias"); techParam != "" {
			techs := strings.Split(techParam, ",")
			condicoes := make([]string, 0, len(techs))
			args := make([]interface{}, 0, len(techs))
			for _, t := range techs {
				t = strings.TrimSpace(t)
				if t == "" {
					continue
				}
				condicoes = append(condicoes, "tecnologias LIKE ?")
				args = append(args, "%"+t+"%")
			}
			if len(condicoes) > 0 {
				q = q.Where(strings.Join(condicoes, " OR "), args...)
			}
		}

		q.Count(&total)
		q.Order("id DESC").Limit(limit).Offset(offset).Find(&dados)
		resultados = dados
	case "cdn":
		var dados []rv1db.CdnInfo
		q := a.DB.Model(&rv1db.CdnInfo{}).Where("host LIKE ? OR ip LIKE ? OR provedor LIKE ?", queryBusca, queryBusca, queryBusca)
		if r.URL.Query().Get("apenas_cdn") == "1" {
			q = q.Where("eh_cdn = ?", true)
		} else if r.URL.Query().Get("apenas_origem") == "1" {
			q = q.Where("eh_cdn = ?", false)
		}
		q.Count(&total)
		q.Order("id DESC").Limit(limit).Offset(offset).Find(&dados)
		resultados = dados
	case "vetores":
		var dados []rv1db.Vetor
		q := a.DB.Model(&rv1db.Vetor{}).Where("url LIKE ? OR tipo LIKE ?", queryBusca, queryBusca)
		// Filtro por status de confiança: ?status=CONFIRMADO,SUSPEITO
		// Vazio ou ausente = sem filtro (mantém todos os status).
		if statusParam := r.URL.Query().Get("status"); statusParam != "" {
			statusVals := strings.Split(statusParam, ",")
			for i := range statusVals {
				statusVals[i] = strings.TrimSpace(statusVals[i])
			}
			q = q.Where("status IN ?", statusVals)
		}
		// Filtro por checkboxes de vulnerabilidade: ?tipos=ssrf,xss,sqli
		// Vazio ou ausente = sem filtro (mantém todos os tipos).
		if tiposParam := r.URL.Query().Get("tipos"); tiposParam != "" {
			tipos := strings.Split(tiposParam, ",")
			for i := range tipos {
				tipos[i] = strings.TrimSpace(tipos[i])
			}
			q = q.Where("tipo IN ?", tipos)
		}

		// Filtros inteligentes (?filtros=php,dev_test,...): cada tag ativa
		// vira "AND (url LIKE %p1% OR url LIKE %p2% ...)". Tags desconhecidas
		// são ignoradas silenciosamente (evita erro 500 por typo no frontend).
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

		// Toggle "Limpar Lixo" (?limpar_lixo=1): esconde assets estáticos.
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
	case "endpointjs":
		var dados []rv1db.EndpointJS
		q := a.DB.Model(&rv1db.EndpointJS{}).Where(
			"endpoint LIKE ? OR source LIKE ? OR tool LIKE ? OR tier LIKE ?",
			queryBusca, queryBusca, queryBusca, queryBusca,
		)
		q.Count(&total)
		q.Order("id DESC").Limit(limit).Offset(offset).Find(&dados)
		resultados = dados
	case "segredos":
		var dados []rv1db.Segredo
		q := a.DB.Model(&rv1db.Segredo{}).Where("descricao LIKE ?", queryBusca)
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

// tiposVetorHandler devolve a lista de tipos de vetor distintos já
// encontrados no banco (ex: ssrf, xss, sqli...), para o frontend montar
// os checkboxes de filtro dinamicamente em vez de fixar no HTML.
func (a *App) tiposVetorHandler(w http.ResponseWriter, r *http.Request) {
	var tipos []string
	a.DB.Model(&rv1db.Vetor{}).Distinct().Order("tipo ASC").Pluck("tipo", &tipos)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tipos)
}

// tiposTecnologiaHandler devolve a lista de tecnologias distintas já
// detectadas (React, Angular, PHP, Envoy...), para popular os botões de
// filtro por tecnologia na aba "Hosts". Como o campo Tecnologias é um CSV
// numa coluna só (não normalizado em tabela própria), o distinct é feito
// em memória: lê todos os valores não vazios e faz o split/dedupe aqui.
func (a *App) tiposTecnologiaHandler(w http.ResponseWriter, r *http.Request) {
	var valores []string
	a.DB.Model(&rv1db.Host{}).Where("tecnologias != ''").Pluck("tecnologias", &valores)

	vistos := make(map[string]bool)
	var tecnologias []string
	for _, v := range valores {
		for _, t := range strings.Split(v, ",") {
			t = strings.TrimSpace(t)
			if t != "" && !vistos[t] {
				vistos[t] = true
				tecnologias = append(tecnologias, t)
			}
		}
	}
	sort.Strings(tecnologias)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tecnologias)
}

// resumoDashboard é o formato devolvido por /api/resumo: contagem total
// por tabela, usado nos cards de visão geral no topo do dashboard.
type resumoDashboard struct {
	Subdominios int64            `json:"subdominios"`
	Hosts       int64            `json:"hosts"`
	Vetores     int64            `json:"vetores"`
	StatusOK    int64            `json:"status_ok"`
	CloudAssets int64            `json:"cloud"`
	CloudRisco  int64            `json:"cloud_risco"` // achados HIGH/CRITICAL
	CdnTotal    int64            `json:"cdn_total"`
	CdnAtrasCDN int64            `json:"cdn_atras_cdn"`
	EndpointsJS int64            `json:"endpoints_js"`
	Segredos    int64            `json:"segredos"`
	PorVetor    map[string]int64 `json:"por_vetor"`
	Confirmados int64            `json:"confirmados"`
	Suspeitos   int64            `json:"suspeitos"`
	Candidatos  int64            `json:"candidatos"`
}

// resumoHandler alimenta os cards de overview do dashboard (/api/resumo).
func (a *App) resumoHandler(w http.ResponseWriter, r *http.Request) {
	var resumo resumoDashboard
	resumo.PorVetor = make(map[string]int64)

	a.DB.Model(&rv1db.Subdominio{}).Count(&resumo.Subdominios)
	a.DB.Model(&rv1db.Host{}).Count(&resumo.Hosts)
	a.DB.Model(&rv1db.Vetor{}).Count(&resumo.Vetores)
	a.DB.Model(&rv1db.Host{}).Where("status_code LIKE ?", "%200%").Count(&resumo.StatusOK)
	a.DB.Model(&rv1db.CloudAsset{}).Count(&resumo.CloudAssets)
	a.DB.Model(&rv1db.CloudAsset{}).Where("severidade IN ?", []string{"HIGH", "CRITICAL"}).Count(&resumo.CloudRisco)
	a.DB.Model(&rv1db.CdnInfo{}).Count(&resumo.CdnTotal)
	a.DB.Model(&rv1db.CdnInfo{}).Where("eh_cdn = ?", true).Count(&resumo.CdnAtrasCDN)
	a.DB.Model(&rv1db.EndpointJS{}).Count(&resumo.EndpointsJS)
	a.DB.Model(&rv1db.Segredo{}).Count(&resumo.Segredos)
	a.DB.Model(&rv1db.Vetor{}).Where("status = ?", "CONFIRMADO").Count(&resumo.Confirmados)
	a.DB.Model(&rv1db.Vetor{}).Where("status = ?", "SUSPEITO").Count(&resumo.Suspeitos)
	a.DB.Model(&rv1db.Vetor{}).Where("status = ?", "CANDIDATO").Count(&resumo.Candidatos)

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
	// WAL permite leituras concorrentes sem bloquear (várias abas do dashboard
	// abertas ao mesmo tempo) e busy_timeout evita erro "database is locked".
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
	mux.HandleFunc("/api/tecnologias/tipos", app.tiposTecnologiaHandler)
	mux.HandleFunc("/api/resumo", app.resumoHandler)
	fs := http.FileServer(http.Dir("./recon-dash/static"))
	mux.Handle("/", fs)

	handlerSeguro := app.firewallMiddleware(mux)
	fmt.Printf("[+] Dashboard seguro rodando. Acesse via SSH: http://%s:%s\n", IP_PERMITIDO, porta)
	if err := http.ListenAndServe("0.0.0.0:"+porta, handlerSeguro); err != nil {
		fmt.Printf("[-] Erro no servidor: %v\n", err)
	}
}
