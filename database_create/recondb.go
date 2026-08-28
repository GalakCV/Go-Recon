package rv1db

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Subdominio struct {
	ID   uint   `gorm:"primaryKey"`
	Host string `gorm:"uniqueIndex"`
}

type Resolvido struct {
	ID   uint   `gorm:"primaryKey"`
	Host string `gorm:"uniqueIndex"`
}

// Host é a visão UNIFICADA de resolvidos + status code + tecnologias,
// pensada pra virar uma única aba no dashboard em vez de três separadas
// (Resolvidos / Status Code / Tecnologias). Populada a partir dos mesmos
// arquivos que já alimentavam as tabelas antigas — Resolvido/Status/
// Tecnologia continuam existindo por compatibilidade, mas o dashboard
// passa a usar esta tabela.
type Host struct {
	ID          uint   `gorm:"primaryKey"`
	Host        string `gorm:"uniqueIndex"`
	StatusCode  string
	Tecnologias string // separadas por vírgula, ex: "React, Nginx, PHP"
}

type Status struct {
	ID         uint   `gorm:"primaryKey"`
	Subdominio string `gorm:"index"`
	StatusCode string
}

type Tecnologia struct {
	ID          uint   `gorm:"primaryKey"`
	Subdominio  string `gorm:"index"`
	Tecnologias string // Guardaremos separadas por vírgula para facilitar
}

type Vetor struct {
	ID        uint   `gorm:"primaryKey"`
	Tipo      string `gorm:"index"` // ex: xss, sqli, lfi, actuator, graphql, admin-panel
	URL       string
	Status    string `gorm:"index"` // CANDIDATO | SUSPEITO | CONFIRMADO
	Evidencia string
}

// CloudAsset guarda cada bucket/conta de nuvem encontrado pelo Cloud Recon
// (rv1-cloud), populado a partir de cloud-recon.json. Os campos de
// permissão (CanList/CanWrite/CanDelete/TakeoverPossivel) refletem o teste
// ativo feito pelo módulo, no mesmo espírito do EnumRust: só reportar
// buckets extraídos de referência real e confirmar o que de fato é
// explorável, não só "existe".
type CloudAsset struct {
	ID               uint   `gorm:"primaryKey"`
	Provider         string `gorm:"index"` // ex: AWS S3, Google Cloud Storage, Azure Blob
	Bucket           string `gorm:"index"`
	URL              string
	StatusCode       int
	Classificacao    string // ex: "Público (listável)", "Privado (existe)"
	Severidade       string // INFO, LOW, MEDIUM, HIGH, CRITICAL
	CanList          bool
	CanWrite         bool
	CanDelete        bool
	TakeoverPossivel bool
	FonteExtracao    string // urls.txt, javascripts/xyz.js...
}

// CdnInfo guarda a classificação CDN x IP de origem de cada host resolvido
// (rv1-cdn), populada a partir de cdn-recon.json. Serve tanto de
// visibilidade no dashboard quanto de base pro futuro port scanner (pular
// IPs de CDN e focar nos hosts com IP de origem real).
type CdnInfo struct {
	ID       uint   `gorm:"primaryKey"`
	Host     string `gorm:"uniqueIndex"`
	IP       string `gorm:"index"`
	Provedor string
	EhCDN    bool `gorm:"index"`
}

// EndpointJS representa um endpoint extraído dos arquivos JavaScript
// (rv1-js-analise), populado a partir de js/sources.jsonl. Mantém a
// proveniência (JS de origem + ferramenta) para auditoria/reprodução.
type EndpointJS struct {
	ID       uint   `gorm:"primaryKey"`
	Endpoint string `gorm:"uniqueIndex"`
	Source   string `gorm:"index"`
	Tool     string
	Tier     string
}

// Segredo representa um secret encontrado nos JS baixados (trufflehog/
// gitleaks), populado a partir de js/secrets.txt.
type Segredo struct {
	ID        uint   `gorm:"primaryKey"`
	Descricao string
}

// EndpointJSJSON é a estrutura de uma linha do js/sources.jsonl.
type EndpointJSJSON struct {
	Endpoint string `json:"endpoint"`
	Source   string `json:"source"`
	Tool     string `json:"tool"`
	Tier     string `json:"tier"`
}

// Estrutura auxiliar para ler o tecnologias.json
type TechJSON struct {
	URL         string   `json:"url"`
	Tecnologias []string `json:"tecnologias"`
}

// Estrutura auxiliar para ler o cloud-recon.json (gerado por rv1-cloud.CloudRecon)
type CloudJSON struct {
	Provider         string `json:"provider"`
	Bucket           string `json:"bucket"`
	URL              string `json:"url"`
	StatusCode       int    `json:"status_code"`
	Classificacao    string `json:"classificacao"`
	Severidade       string `json:"severidade"`
	CanList          bool   `json:"can_list"`
	CanWrite         bool   `json:"can_write"`
	CanDelete        bool   `json:"can_delete"`
	TakeoverPossivel bool   `json:"takeover_possivel"`
	FonteExtracao    string `json:"fonte_extracao"`
}

// Estrutura auxiliar para ler o cdn-recon.json (gerado por rv1-cdn.FiltrarCDN)
type CdnJSON struct {
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Provedor string `json:"provedor"`
	EhCDN    bool   `json:"eh_cdn"`
}

// tamanhoLote define quantos registros entram em cada transação.
// Antes cada linha do arquivo virava um db.Create() isolado, e no SQLite
// isso significa uma transação implícita (com fsync) por linha — em uma
// base com dezenas de milhares de subdomínios isso é o maior gargalo da
// etapa de população do banco.
const tamanhoLote = 500

// --- Função Principal ---

// PopularBanco lê os arquivos de resultado e insere no SQLite
func PopularBanco(ctx context.Context, empresa string) {
	fmt.Println("\n[+] Iniciando estruturação do Banco de Dados SQLite...")

	dbPath := filepath.Join(empresa, empresa+".db")
	dsn := dbPath + "?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent), // Silencia os logs do GORM para não poluir o terminal
	})
	if err != nil {
		fmt.Printf("[-] Erro ao conectar no SQLite: %v\n", err)
		return
	}

	// Cria as tabelas automaticamente
	db.AutoMigrate(&Subdominio{}, &Resolvido{}, &Host{}, &Status{}, &Tecnologia{}, &Vetor{}, &CloudAsset{}, &CdnInfo{}, &EndpointJS{}, &Segredo{})

	resultadosDir := filepath.Join(empresa, "resultados")

	// 1. Inserir Subdomínios
	fmt.Println("[*] Populando tabela: Subdominios...")
	inserirTxtSimples(db, filepath.Join(resultadosDir, "subdominios.txt"), func(linha string) interface{} {
		return &Subdominio{Host: linha}
	})

	// 2. Inserir Resolvidos
	fmt.Println("[*] Populando tabela: Resolvidos...")
	inserirTxtSimples(db, filepath.Join(resultadosDir, "resolvidos.txt"), func(linha string) interface{} {
		return &Resolvido{Host: linha}
	})

	// 3. Inserir Status Code
	fmt.Println("[*] Populando tabela: Status...")
	inserirStatus(db, filepath.Join(resultadosDir, "statuscode-httpx.txt"))

	// 4. Inserir Tecnologias
	fmt.Println("[*] Populando tabela: Tecnologias...")
	inserirTecnologias(db, filepath.Join(resultadosDir, "tecnologias.json"))

	// 4b. Inserir a visão unificada Host (resolvidos + status + tecnologias
	// mesclados por nome de host), usada pela nova aba "Hosts" do dashboard.
	fmt.Println("[*] Populando tabela: Hosts (visão unificada)...")
	inserirHosts(db, resultadosDir)

	// 5. Inserir Vetores de Ataque (inclui admin-panel.txt, actuator.txt e
	// graphql.txt, gerados por rv1-admin e rv1-disclosure — mesmo formato
	// dos outros arquivos de vetor, então entram automaticamente aqui)
	fmt.Println("[*] Populando tabela: Vetores...")
	inserirVetores(db, filepath.Join(resultadosDir, "vetores_ataque"))

	// 6. Inserir Cloud Recon (buckets/contas encontrados por rv1-cloud.CloudRecon)
	fmt.Println("[*] Populando tabela: CloudAssets...")
	inserirCloud(db, filepath.Join(resultadosDir, "cloud-recon.json"))

	// 7. Inserir classificação de CDN (rv1-cdn.FiltrarCDN)
	fmt.Println("[*] Populando tabela: CdnInfo...")
	inserirCdn(db, filepath.Join(resultadosDir, "cdn-recon.json"))

	// 8. Inserir endpoints extraídos do JavaScript (rv1-js-analise)
	fmt.Println("[*] Populando tabela: EndpointsJS...")
	inserirEndpointsJS(db, filepath.Join(resultadosDir, "js", "sources.jsonl"))

	// 9. Inserir segredos encontrados nos JS (rv1-js-analise)
	fmt.Println("[*] Populando tabela: Segredos...")
	inserirSegredos(db, filepath.Join(resultadosDir, "js", "secrets.txt"))

	fmt.Printf("[+] Banco de dados '%s' populado com sucesso!\n", dbPath)
}

// inserirLote grava um lote inteiro dentro de UMA transação.
// Duplicados (violação de uniqueIndex, ex: Host repetido) são ignorados
// silenciosamente; qualquer outro erro é reportado sem abortar o lote inteiro.
func inserirLote(db *gorm.DB, lote []interface{}) {
	if len(lote) == 0 {
		return
	}
	db.Transaction(func(tx *gorm.DB) error {
		for _, item := range lote {
			if err := tx.Create(item).Error; err != nil {
				if !strings.Contains(err.Error(), "UNIQUE constraint") {
					fmt.Printf("[-] Erro ao inserir registro: %v\n", err)
				}
				continue
			}
		}
		return nil
	})
}

func inserirTxtSimples(db *gorm.DB, caminho string, construtor func(string) interface{}) {
	arquivo, err := os.Open(caminho)
	if err != nil {
		return
	}
	defer arquivo.Close()

	lote := make([]interface{}, 0, tamanhoLote)

	scanner := bufio.NewScanner(arquivo)
	for scanner.Scan() {
		linha := strings.TrimSpace(scanner.Text())
		if linha == "" {
			continue
		}
		lote = append(lote, construtor(linha))
		if len(lote) >= tamanhoLote {
			inserirLote(db, lote)
			lote = lote[:0]
		}
	}
	inserirLote(db, lote)

	if err := scanner.Err(); err != nil {
		fmt.Printf("[-] Erro durante a leitura do arquivo %s: %v\n", caminho, err)
	}
}

func inserirStatus(db *gorm.DB, caminho string) {
	arquivo, err := os.Open(caminho)
	if err != nil {
		return
	}
	defer arquivo.Close()

	lote := make([]interface{}, 0, tamanhoLote)

	scanner := bufio.NewScanner(arquivo)
	for scanner.Scan() {
		linha := strings.TrimSpace(scanner.Text())
		if linha == "" {
			continue
		}
		partes := strings.Split(linha, " [")
		if len(partes) == 2 {
			subdominio := strings.TrimSpace(partes[0])
			codigo := strings.TrimRight(partes[1], "]")
			lote = append(lote, &Status{Subdominio: subdominio, StatusCode: codigo})
			if len(lote) >= tamanhoLote {
				inserirLote(db, lote)
				lote = lote[:0]
			}
		}
	}
	inserirLote(db, lote)

	if err := scanner.Err(); err != nil {
		fmt.Printf("[-] Erro durante a leitura do arquivo %s: %v\n", caminho, err)
	}
}

func inserirTecnologias(db *gorm.DB, caminho string) {
	conteudo, err := os.ReadFile(caminho)
	if err != nil {
		return
	}

	var techs []TechJSON
	if err := json.Unmarshal(conteudo, &techs); err != nil {
		fmt.Printf("[-] Erro ao ler JSON de tecnologias: %v\n", err)
		return
	}

	lote := make([]interface{}, 0, tamanhoLote)
	for _, t := range techs {
		techStr := strings.Join(t.Tecnologias, ", ")
		lote = append(lote, &Tecnologia{Subdominio: t.URL, Tecnologias: techStr})
		if len(lote) >= tamanhoLote {
			inserirLote(db, lote)
			lote = lote[:0]
		}
	}
	inserirLote(db, lote)
}

// inserirHosts mescla resolvidos.txt + statuscode-httpx.txt + tecnologias.json
// num único mapa por nome de host e popula a tabela Host — a visão
// unificada que substitui as três abas separadas no dashboard.
func inserirHosts(db *gorm.DB, resultadosDir string) {
	hosts := make(map[string]*Host)

	// Base: todo host resolvido entra na lista, mesmo sem status/tech ainda.
	if arquivo, err := os.Open(filepath.Join(resultadosDir, "resolvidos.txt")); err == nil {
		scanner := bufio.NewScanner(arquivo)
		for scanner.Scan() {
			h := strings.TrimSpace(scanner.Text())
			if h != "" {
				hosts[h] = &Host{Host: h}
			}
		}
		arquivo.Close()
	}

	// Status code.
	if arquivo, err := os.Open(filepath.Join(resultadosDir, "statuscode-httpx.txt")); err == nil {
		scanner := bufio.NewScanner(arquivo)
		for scanner.Scan() {
			linha := strings.TrimSpace(scanner.Text())
			partes := strings.Split(linha, " [")
			if len(partes) != 2 {
				continue
			}
			sub := strings.TrimSpace(partes[0])
			codigo := strings.TrimRight(partes[1], "]")
			if h, ok := hosts[sub]; ok {
				h.StatusCode = codigo
			} else {
				hosts[sub] = &Host{Host: sub, StatusCode: codigo}
			}
		}
		arquivo.Close()
	}

	// Tecnologias.
	if conteudo, err := os.ReadFile(filepath.Join(resultadosDir, "tecnologias.json")); err == nil {
		var techs []TechJSON
		if json.Unmarshal(conteudo, &techs) == nil {
			for _, t := range techs {
				techStr := strings.Join(t.Tecnologias, ", ")
				if h, ok := hosts[t.URL]; ok {
					h.Tecnologias = techStr
				} else {
					hosts[t.URL] = &Host{Host: t.URL, Tecnologias: techStr}
				}
			}
		}
	}

	lote := make([]interface{}, 0, tamanhoLote)
	for _, h := range hosts {
		lote = append(lote, h)
		if len(lote) >= tamanhoLote {
			inserirLote(db, lote)
			lote = lote[:0]
		}
	}
	inserirLote(db, lote)
}

// inserirCdn lê o cdn-recon.json (gerado por rv1-cdn.FiltrarCDN) e popula
// a tabela CdnInfo. Sem o arquivo (etapa nunca rodou), não faz nada.
func inserirCdn(db *gorm.DB, caminho string) {
	conteudo, err := os.ReadFile(caminho)
	if err != nil {
		return
	}
	var achados []CdnJSON
	if err := json.Unmarshal(conteudo, &achados); err != nil {
		fmt.Printf("[-] Erro ao ler JSON de CDN: %v\n", err)
		return
	}
	lote := make([]interface{}, 0, tamanhoLote)
	for _, a := range achados {
		lote = append(lote, &CdnInfo{Host: a.Host, IP: a.IP, Provedor: a.Provedor, EhCDN: a.EhCDN})
		if len(lote) >= tamanhoLote {
			inserirLote(db, lote)
			lote = lote[:0]
		}
	}
	inserirLote(db, lote)
}

// inserirCloud lê o cloud-recon.json (gerado por rv1-cloud.CloudRecon) e
// popula a tabela CloudAsset. Se o arquivo não existir (Cloud Recon nunca
// rodou), simplesmente não faz nada — mesmo comportamento das outras etapas.
func inserirCloud(db *gorm.DB, caminho string) {
	conteudo, err := os.ReadFile(caminho)
	if err != nil {
		return
	}

	var achados []CloudJSON
	if err := json.Unmarshal(conteudo, &achados); err != nil {
		fmt.Printf("[-] Erro ao ler JSON de cloud recon: %v\n", err)
		return
	}

	lote := make([]interface{}, 0, tamanhoLote)
	for _, a := range achados {
		lote = append(lote, &CloudAsset{
			Provider:         a.Provider,
			Bucket:           a.Bucket,
			URL:              a.URL,
			StatusCode:       a.StatusCode,
			Classificacao:    a.Classificacao,
			Severidade:       a.Severidade,
			CanList:          a.CanList,
			CanWrite:         a.CanWrite,
			CanDelete:        a.CanDelete,
			TakeoverPossivel: a.TakeoverPossivel,
			FonteExtracao:    a.FonteExtracao,
		})
		if len(lote) >= tamanhoLote {
			inserirLote(db, lote)
			lote = lote[:0]
		}
	}
	inserirLote(db, lote)
}

// fileExiste é um helper simples para checar a existência de um arquivo.
func fileExiste(caminho string) bool {
	_, err := os.Stat(caminho)
	return err == nil
}

// inserirVetores lê o arquivo vetores.jsonl (gerado pelo novo pipeline de
// vetores em rv1-validacao) e popula a tabela Vetor com status/evidência.
// Mantém retrocompatibilidade com os arquivos *.txt do fluxo antigo (gf),
// que nesse caso entram como status CANDIDATO.
func inserirVetores(db *gorm.DB, pastaVetores string) {
	jsonl := filepath.Join(pastaVetores, "vetores.jsonl")
	if fileExiste(jsonl) {
		inserirVetoresJSONL(db, jsonl)
		// não lê os .txt antigos se o pipeline novo já gerou o JSONL
		return
	}

	// fluxo antigo (fallback): *.txt -> status CANDIDATO
	arquivos, err := os.ReadDir(pastaVetores)
	if err != nil {
		return
	}
	for _, req := range arquivos {
		if !req.IsDir() && strings.HasSuffix(req.Name(), ".txt") {
			tipoVetor := strings.TrimSuffix(req.Name(), ".txt")
			caminhoArquivo := filepath.Join(pastaVetores, req.Name())
			inserirTxtSimples(db, caminhoArquivo, func(linha string) interface{} {
				return &Vetor{Tipo: tipoVetor, URL: linha, Status: "CANDIDATO"}
			})
		}
	}
}

// inserirVetoresJSONL lê vetores.jsonl (uma linha JSON com tipo/url/status/
// evidencia) e insere na tabela Vetor.
func inserirVetoresJSONL(db *gorm.DB, caminho string) {
	arquivo, err := os.Open(caminho)
	if err != nil {
		return
	}
	defer arquivo.Close()

	lote := make([]interface{}, 0, tamanhoLote)
	scanner := bufio.NewScanner(arquivo)
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)

	for scanner.Scan() {
		linha := strings.TrimSpace(scanner.Text())
		if linha == "" {
			continue
		}
		var v struct {
			Tipo      string `json:"tipo"`
			URL       string `json:"url"`
			Status    string `json:"status"`
			Evidencia string `json:"evidencia"`
		}
		if err := json.Unmarshal([]byte(linha), &v); err != nil || v.URL == "" {
			continue
		}
		status := v.Status
		if status == "" {
			status = "CANDIDATO"
		}
		lote = append(lote, &Vetor{
			Tipo:      v.Tipo,
			URL:       v.URL,
			Status:    status,
			Evidencia: v.Evidencia,
		})
		if len(lote) >= tamanhoLote {
			inserirLote(db, lote)
			lote = lote[:0]
		}
	}
	inserirLote(db, lote)

	if err := scanner.Err(); err != nil {
		fmt.Printf("[-] Erro lendo vetores.jsonl: %v\n", err)
	}
}

// inserirEndpointsJS lê o js/sources.jsonl (gerado por rv1-js-analise) e
// popula a tabela EndpointJS. Cada linha é um JSON com endpoint/source/
// tool/tier. Sem o arquivo, não faz nada.
//
// CORREÇÃO: a tabela nunca era limpa entre execuções, então rodar o
// pipeline de novo (ex: depois de um filtro de escopo mais rígido)
// simplesmente ACRESCENTAVA linhas nas já existentes — o lixo de uma
// execução antiga continuava aparecendo no painel ao lado dos dados novos.
// sources.jsonl já é o snapshot completo e atual, então a tabela é limpa
// antes de reinserir.
func inserirEndpointsJS(db *gorm.DB, caminho string) {
	if err := db.Where("1 = 1").Delete(&EndpointJS{}).Error; err != nil {
		fmt.Printf("[-] Erro limpando tabela EndpointsJS antes de repopular: %v\n", err)
	}

	arquivo, err := os.Open(caminho)
	if err != nil {
		return
	}
	defer arquivo.Close()

	lote := make([]interface{}, 0, tamanhoLote)
	scanner := bufio.NewScanner(arquivo)
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)

	for scanner.Scan() {
		linha := strings.TrimSpace(scanner.Text())
		if linha == "" {
			continue
		}
		var e EndpointJSJSON
		if err := json.Unmarshal([]byte(linha), &e); err != nil {
			continue
		}
		if e.Endpoint == "" {
			continue
		}
		lote = append(lote, &EndpointJS{
			Endpoint: e.Endpoint,
			Source:   e.Source,
			Tool:     e.Tool,
			Tier:     e.Tier,
		})
		if len(lote) >= tamanhoLote {
			inserirLote(db, lote)
			lote = lote[:0]
		}
	}
	inserirLote(db, lote)

	if err := scanner.Err(); err != nil {
		fmt.Printf("[-] Erro lendo sources.jsonl: %v\n", err)
	}
}

// inserirSegredos lê o js/secrets.txt (gerado por rv1-js-analise) e popula
// a tabela Segredo. Cada linha vira um registro.
func inserirSegredos(db *gorm.DB, caminho string) {
	inserirTxtSimples(db, caminho, func(linha string) interface{} {
		return &Segredo{Descricao: linha}
	})
}
