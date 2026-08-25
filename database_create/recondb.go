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

// Estrutura auxiliar para ler o tecnologias.json
type TechJSON struct {
	URL         string   `json:"url"`
	Tecnologias []string `json:"tecnologias"`
}

// --- Função Principal ---

// PopularBanco lê os arquivos de resultado e insere no SQLite
func PopularBanco(ctx context.Context, empresa string) {
	fmt.Println("\n[+] Iniciando estruturação do Banco de Dados SQLite...")

	dbPath := filepath.Join(empresa, empresa+".db") // ex: google/google.db
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: nil, // Silencia os logs do GORM para não poluir o terminal
	})
	if err != nil {
		fmt.Printf("[-] Erro ao conectar no SQLite: %v\n", err)
		return
	}

	// Cria as tabelas automaticamente
	db.AutoMigrate(&Subdominio{}, &Resolvido{}, &Status{}, &Tecnologia{}, &Vetor{})

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

	fmt.Printf("[+] Banco de dados '%s' populado com sucesso!\n", dbPath)
}

func inserirTxtSimples(db *gorm.DB, caminho string, construtor func(string) interface{}) {
	arquivo, err := os.Open(caminho)
	if err != nil {
		return
	}
	defer arquivo.Close()

	scanner := bufio.NewScanner(arquivo)
	for scanner.Scan() {
		linha := strings.TrimSpace(scanner.Text())
		if linha != "" {
			db.Create(construtor(linha))
		}
	}

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
			db.Create(&Status{Subdominio: subdominio, StatusCode: codigo})
		}
	}
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

	for _, t := range techs {
		if len(t.Tecnologias) > 0 {
			techStr := strings.Join(t.Tecnologias, ", ")
			db.Create(&Tecnologia{Subdominio: t.URL, Tecnologias: techStr})
		} else {
			// Se estiver vazio, gravamos "Nenhuma" ou ignoramos. Aqui vamos gravar como vazio.
			db.Create(&Tecnologia{Subdominio: t.URL, Tecnologias: ""})
		}
	}
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