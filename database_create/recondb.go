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
	ID   uint   `gorm:"primaryKey"`
	Tipo string `gorm:"index"` // ex: xss, sqli, lfi
	URL  string
}

// CloudAsset guarda cada bucket/conta de nuvem encontrado pelo Cloud Recon
// (rv1-cloud), populado a partir de cloud-recon.json.
type CloudAsset struct {
	ID            uint   `gorm:"primaryKey"`
	Provider      string `gorm:"index"` // ex: AWS S3, Google Cloud Storage, Azure Blob
	Bucket        string `gorm:"index"`
	URL           string
	StatusCode    int
	Classificacao string // ex: "Público (listável)", "Privado (existe)"
}

// Estrutura auxiliar para ler o tecnologias.json
type TechJSON struct {
	URL         string   `json:"url"`
	Tecnologias []string `json:"tecnologias"`
}

// Estrutura auxiliar para ler o cloud-recon.json (gerado por rv1-cloud.CloudRecon)
type CloudJSON struct {
	Provider      string `json:"provider"`
	Bucket        string `json:"bucket"`
	URL           string `json:"url"`
	StatusCode    int    `json:"status_code"`
	Classificacao string `json:"classificacao"`
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
	db.AutoMigrate(&Subdominio{}, &Resolvido{}, &Status{}, &Tecnologia{}, &Vetor{}, &CloudAsset{})

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

	// 5. Inserir Vetores de Ataque
	fmt.Println("[*] Populando tabela: Vetores...")
	inserirVetores(db, filepath.Join(resultadosDir, "vetores_ataque"))

	// 6. Inserir Cloud Recon (buckets/contas encontrados por rv1-cloud.CloudRecon)
	fmt.Println("[*] Populando tabela: CloudAssets...")
	inserirCloud(db, filepath.Join(resultadosDir, "cloud-recon.json"))

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
			Provider:      a.Provider,
			Bucket:        a.Bucket,
			URL:           a.URL,
			StatusCode:    a.StatusCode,
			Classificacao: a.Classificacao,
		})
		if len(lote) >= tamanhoLote {
			inserirLote(db, lote)
			lote = lote[:0]
		}
	}
	inserirLote(db, lote)
}

func inserirVetores(db *gorm.DB, pastaVetores string) {
	arquivos, err := os.ReadDir(pastaVetores)
	if err != nil {
		return
	}

	for _, req := range arquivos {
		if !req.IsDir() && strings.HasSuffix(req.Name(), ".txt") {
			tipoVetor := strings.TrimSuffix(req.Name(), ".txt")
			caminhoArquivo := filepath.Join(pastaVetores, req.Name())

			inserirTxtSimples(db, caminhoArquivo, func(linha string) interface{} {
				return &Vetor{Tipo: tipoVetor, URL: linha}
			})
		}
	}
}
