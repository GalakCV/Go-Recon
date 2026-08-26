package rv1cloud

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)
type Achado struct {
	Provider      string `json:"provider"`
	Bucket        string `json:"bucket"`
	URL           string `json:"url"`
	StatusCode    int    `json:"status_code"`
	Classificacao string `json:"classificacao"`
}

type provedor struct {
	nome        string
	montarURL   func(candidato string) string
	classificar func(status int) (classificacao string, relevante bool)
}

var provedores = []provedor{
	{
		nome:      "AWS S3",
		montarURL: func(c string) string { return fmt.Sprintf("https://%s.s3.amazonaws.com/", c) },
		classificar: func(status int) (string, bool) {
			switch status {
			case 200:
				return "Público (listável)", true
			case 403:
				return "Privado (existe)", true
			default:
				return "", false
			}
		},
	},
	{
		nome:      "Google Cloud Storage",
		montarURL: func(c string) string { return fmt.Sprintf("https://storage.googleapis.com/%s", c) },
		classificar: func(status int) (string, bool) {
			switch status {
			case 200:
				return "Público (listável)", true
			case 403:
				return "Privado (existe)", true
			default:
				return "", false
			}
		},
	},
	{
		nome: "Azure Blob",
		montarURL: func(c string) string {
			// Assume a convenção comum de container com o mesmo nome da conta.
			return fmt.Sprintf("https://%s.blob.core.windows.net/%s?restype=container&comp=list", c, c)
		},
		classificar: func(status int) (string, bool) {
			switch status {
			case 200:
				return "Público (listável)", true
			case 403:
				return "Privado (existe)", true
			case 400:
				// Conta existe mas o container/nome não bate ou a request
				// precisa de auth — ainda assim confirma que a conta existe.
				return "Conta existe (config)", true
			default:
				return "", false
			}
		},
	},
}

// sufixos geram variações de nome de bucket a partir de cada nome-base.
var sufixos = []string{
	"", "-dev", "-prod", "-production", "-staging", "-test", "-backup", "-backups",
	"-assets", "-static", "-media", "-uploads", "-files", "-data", "-www", "-api",
	"-cdn", "-images", "-img", "-public", "-private", "-internal", "-logs", "-old",
	"-new", "-storage", "-bucket", "-web", "-app", "-docs", "-config",
}

// labelsIgnorados são rótulos de subdomínio genéricos demais pra virar
// candidato de bucket (só geram ruído).
var labelsIgnorados = map[string]bool{
	"www": true, "mail": true, "ftp": true, "ns1": true, "ns2": true, "ns3": true,
	"cdn": true, "mx": true, "smtp": true, "webmail": true, "autodiscover": true,
}

const (
	maxCandidatosBase    = 25 // limite de nomes-base (empresa + labels de subdomínio)
	concorrencia         = 20
	timeoutPorRequisicao = 6 * time.Second
)

// normalizar prepara uma string pra virar candidato de nome de bucket:
// minúsculo, sem espaço, só [a-z0-9-].
func normalizar(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var sb strings.Builder
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-':
			sb.WriteRune(r)
		case r == ' ' || r == '_':
			sb.WriteRune('-')
		}
	}
	return strings.Trim(sb.String(), "-")
}

// candidatosBase monta a lista de nomes-base: variações do nome da empresa
// mais os primeiros rótulos dos subdomínios já descobertos no pipeline
// (subdominios.txt), já que produtos/marcas internas costumam repetir nome
// de bucket.
func candidatosBase(empresa, resultadosDir string) []string {
	vistos := make(map[string]bool)
	var base []string

	add := func(c string) {
		c = normalizar(c)
		if c == "" || len(c) < 3 || vistos[c] || labelsIgnorados[c] {
			return
		}
		vistos[c] = true
		base = append(base, c)
	}

	add(empresa)
	add(strings.ReplaceAll(empresa, " ", ""))

	subdominiosTxt := filepath.Join(resultadosDir, "subdominios.txt")
	if arquivo, err := os.Open(subdominiosTxt); err == nil {
		defer arquivo.Close()
		scanner := bufio.NewScanner(arquivo)
		for scanner.Scan() && len(base) < maxCandidatosBase {
			host := strings.TrimSpace(scanner.Text())
			if partes := strings.Split(host, "."); len(partes) > 0 {
				add(partes[0])
			}
		}
	}

	if len(base) > maxCandidatosBase {
		base = base[:maxCandidatosBase]
	}
	return base
}

func CloudRecon(ctx context.Context, empresa string) {
	fmt.Println("\n[+] Iniciando Cloud Recon (S3 / GCS / Azure Blob)...")

	resultadosDir := filepath.Join(empresa, "resultados")
	if err := os.MkdirAll(resultadosDir, 0755); err != nil {
		fmt.Printf("[-] Erro criando diretório de resultados: %v\n", err)
		return
	}
	outputFile := filepath.Join(resultadosDir, "cloud-recon.json")

	base := candidatosBase(empresa, resultadosDir)
	if len(base) == 0 {
		fmt.Println("[-] Nenhum candidato de nome gerado (empresa vazia e sem subdominios.txt). Abortando.")
		return
	}

	var candidatos []string
	for _, b := range base {
		for _, suf := range sufixos {
			candidatos = append(candidatos, b+suf)
		}
	}

	totalProbes := len(candidatos) * len(provedores)
	fmt.Printf("[*] %d nomes-base, %d combinações, %d provedores -> %d requisições\n",
		len(base), len(candidatos), len(provedores), totalProbes)

	client := &http.Client{Timeout: timeoutPorRequisicao}

	var (
		mu       sync.Mutex
		achados  []Achado
		checados int
	)
	sem := make(chan struct{}, concorrencia)
	var wg sync.WaitGroup
	cancelado := false

loopCandidatos:
	for _, candidato := range candidatos {
		for _, prov := range provedores {
			select {
			case <-ctx.Done():
				cancelado = true
				break loopCandidatos
			default:
			}

			wg.Add(1)
			sem <- struct{}{}
			go func(candidato string, prov provedor) {
				defer wg.Done()
				defer func() { <-sem }()

				url := prov.montarURL(candidato)
				reqCtx, cancel := context.WithTimeout(ctx, timeoutPorRequisicao)
				defer cancel()

				req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
				if err != nil {
					return
				}
				resp, err := client.Do(req)

				mu.Lock()
				checados++
				mu.Unlock()

				if err != nil {
					return
				}
				defer resp.Body.Close()

				classificacao, relevante := prov.classificar(resp.StatusCode)
				if !relevante {
					return
				}

				mu.Lock()
				achados = append(achados, Achado{
					Provider:      prov.nome,
					Bucket:        candidato,
					URL:           url,
					StatusCode:    resp.StatusCode,
					Classificacao: classificacao,
				})
				mu.Unlock()

				fmt.Printf("[+] %s: %s (%s, HTTP %d)\n", prov.nome, candidato, classificacao, resp.StatusCode)
			}(candidato, prov)
		}
	}

	wg.Wait()

	if cancelado {
		fmt.Printf("\n[!] Cloud Recon cancelado pelo usuário (CTRL + C). %d requisições concluídas antes de parar.\n", checados)
	}

	sort.Slice(achados, func(i, j int) bool {
		if achados[i].Provider != achados[j].Provider {
			return achados[i].Provider < achados[j].Provider
		}
		return achados[i].Bucket < achados[j].Bucket
	})

	dados, err := json.MarshalIndent(achados, "", "  ")
	if err != nil {
		fmt.Printf("[-] Erro ao serializar resultados: %v\n", err)
		return
	}
	if err := os.WriteFile(outputFile, dados, 0644); err != nil {
		fmt.Printf("[-] Erro ao salvar %s: %v\n", outputFile, err)
		return
	}

	fmt.Printf("[+] Cloud Recon finalizado: %d achados salvos em %s\n", len(achados), outputFile)
}
