package rv1cloud

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Achado representa um asset de nuvem encontrado (bucket S3, storage GCS,
// conta/container Azure Blob...) e é o formato salvo em cloud-recon.json,
// depois lido por database_create.PopularBanco (inserirCloud).
//
// Diferente da v1 (que ADIVINHAVA nomes de bucket a partir da empresa +
// sufixos), esta versão segue a técnica usada pelo EnumRust (Ofjaaah): só
// testa buckets que JÁ aparecem referenciados em algo que o pipeline
// coletou (urls.txt e o JS baixado por rv1-js-analise). Isso elimina o
// ruído de nomes genéricos ("beta", "beta-dev"...) que colidem com buckets
// de QUALQUER outra empresa na AWS — nome de bucket é único globalmente,
// não por conta, então um 403 num nome adivinhado não prova relação com o
// alvo. Um bucket EXTRAÍDO do código do alvo, por outro lado, é
// garantidamente relevante.
type Achado struct {
	Provider         string `json:"provider"`
	Bucket           string `json:"bucket"`
	URL              string `json:"url"`
	StatusCode       int    `json:"status_code"`
	Classificacao    string `json:"classificacao"`
	Severidade       string `json:"severidade"` // INFO, LOW, MEDIUM, HIGH, CRITICAL
	CanList          bool   `json:"can_list"`
	CanWrite         bool   `json:"can_write"`
	CanDelete        bool   `json:"can_delete"`
	TakeoverPossivel bool   `json:"takeover_possivel"`
	FonteExtracao    string `json:"fonte_extracao"` // de onde a referência foi extraída
}

// extrator descreve o regex usado pra achar referências de um provedor de
// nuvem em texto livre (URLs coletadas, JS baixado) e como montar a URL
// "raiz" do bucket a partir do nome extraído, pra sondar depois.
type extrator struct {
	provider  string
	regex     *regexp.Regexp
	montarURL func(bucket string) string
}

var extratores = []extrator{
	{
		provider:  "AWS S3",
		regex:     regexp.MustCompile(`([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[.\-][a-z0-9\-]*\.amazonaws\.com`),
		montarURL: func(b string) string { return fmt.Sprintf("https://%s.s3.amazonaws.com/", b) },
	},
	{
		provider:  "AWS S3",
		regex:     regexp.MustCompile(`s3[.\-][a-z0-9\-]*\.amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])`),
		montarURL: func(b string) string { return fmt.Sprintf("https://%s.s3.amazonaws.com/", b) },
	},
	{
		provider:  "Google Cloud Storage",
		regex:     regexp.MustCompile(`storage\.googleapis\.com/([a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])`),
		montarURL: func(b string) string { return fmt.Sprintf("https://storage.googleapis.com/%s", b) },
	},
	{
		provider:  "Google Cloud Storage",
		regex:     regexp.MustCompile(`([a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])\.storage\.googleapis\.com`),
		montarURL: func(b string) string { return fmt.Sprintf("https://storage.googleapis.com/%s", b) },
	},
	{
		provider: "Azure Blob",
		regex:    regexp.MustCompile(`([a-z0-9]{3,24})\.blob\.core\.windows\.net`),
		montarURL: func(b string) string {
			return fmt.Sprintf("https://%s.blob.core.windows.net/%s?restype=container&comp=list", b, b)
		},
	},
	{
		provider:  "DigitalOcean Spaces",
		regex:     regexp.MustCompile(`([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.[a-z0-9\-]+\.digitaloceanspaces\.com`),
		montarURL: func(b string) string { return fmt.Sprintf("https://%s.digitaloceanspaces.com/", b) },
	},
	{
		provider:  "Cloudflare R2",
		regex:     regexp.MustCompile(`([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.r2\.cloudflarestorage\.com`),
		montarURL: func(b string) string { return fmt.Sprintf("https://%s.r2.cloudflarestorage.com/", b) },
	},
	{
		provider:  "Alibaba OSS",
		regex:     regexp.MustCompile(`([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.oss-[a-z0-9\-]+\.aliyuncs\.com`),
		montarURL: func(b string) string { return fmt.Sprintf("https://%s.aliyuncs.com/", b) },
	},
}

const (
	concorrencia         = 15
	timeoutPorRequisicao = 8 * time.Second
)

// candidato é uma referência de bucket já extraída, antes de ser sondada.
type candidato struct {
	provider string
	bucket   string
	url      string
	fonte    string
}

// extrairCandidatos varre um texto em busca de referências de bucket usando
// todos os extratores. Retorna zero ou mais candidatos (um texto pode
// referenciar vários buckets, ex: um bundle JS grande).
func extrairCandidatos(texto, fonte string) []candidato {
	var achados []candidato
	for _, ex := range extratores {
		for _, m := range ex.regex.FindAllStringSubmatch(texto, -1) {
			if len(m) < 2 {
				continue
			}
			bucket := strings.ToLower(m[1])
			achados = append(achados, candidato{
				provider: ex.provider,
				bucket:   bucket,
				url:      ex.montarURL(bucket),
				fonte:    fonte,
			})
		}
	}
	return achados
}

// coletarCandidatos lê urls.txt e todos os .js já baixados por rv1-js-analise
// (BaixarJS) em busca de referências de bucket, deduplicando por
// provider+bucket.
func coletarCandidatos(resultadosDir string) []candidato {
	vistos := make(map[string]bool)
	var todos []candidato

	add := func(lista []candidato) {
		for _, c := range lista {
			chave := c.provider + "|" + c.bucket
			if !vistos[chave] {
				vistos[chave] = true
				todos = append(todos, c)
			}
		}
	}

	// Fonte 1: urls.txt (endpoints/URLs já agregados pelo pipeline)
	if arquivo, err := os.Open(filepath.Join(resultadosDir, "urls.txt")); err == nil {
		scanner := bufio.NewScanner(arquivo)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)
		for scanner.Scan() {
			add(extrairCandidatos(scanner.Text(), "urls.txt"))
		}
		arquivo.Close()
	}

	// Fonte 2: JS baixado (resultados/javascripts/*.js) — é onde mais
	// aparece referência direta a bucket (SDK configurado no client-side,
	// upload direto de arquivo pro storage, etc.)
	jsDir := filepath.Join(resultadosDir, "javascripts")
	if entradas, err := os.ReadDir(jsDir); err == nil {
		for _, e := range entradas {
			if e.IsDir() {
				continue
			}
			caminho := filepath.Join(jsDir, e.Name())
			conteudo, err := os.ReadFile(caminho)
			if err != nil {
				continue
			}
			add(extrairCandidatos(string(conteudo), "javascripts/"+e.Name()))
		}
	}

	return todos
}

// testarPermissoes sonda um candidato e classifica o achado. testarEscrita
// controla se um PUT/DELETE de teste é enviado — desligado por padrão
// porque, diferente de LIST, isso é uma ação ativa contra a infraestrutura
// de armazenamento do alvo (grava e depois apaga um arquivo de teste). Só
// ligue em programas de bug bounty que autorizam teste ativo.
func testarPermissoes(ctx context.Context, client *http.Client, c candidato, testarEscrita bool) *Achado {
	reqCtx, cancel := context.WithTimeout(ctx, timeoutPorRequisicao)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	corpo, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	corpoStr := string(corpo)

	achado := &Achado{
		Provider:      c.provider,
		Bucket:        c.bucket,
		URL:           c.url,
		StatusCode:    resp.StatusCode,
		FonteExtracao: c.fonte,
	}

	switch {
	case resp.StatusCode == 404 && (strings.Contains(corpoStr, "NoSuchBucket") ||
		strings.Contains(corpoStr, "notFound") ||
		strings.Contains(corpoStr, "does not exist") ||
		strings.Contains(corpoStr, "BucketNotFound")):
		// Referenciado no código do alvo, mas o bucket não existe mais:
		// qualquer um pode criar esse nome e sequestrar o conteúdo servido
		// pelo domínio do alvo (clássico "S3 bucket takeover").
		achado.TakeoverPossivel = true
		achado.Classificacao = "Possível takeover (referenciado, mas não existe)"
		achado.Severidade = "CRITICAL"

	case resp.StatusCode == 200:
		achado.CanList = true
		achado.Classificacao = "Público (listável)"
		achado.Severidade = "HIGH"

	case resp.StatusCode == 403:
		achado.Classificacao = "Privado (existe, sem listagem anônima)"
		achado.Severidade = "INFO"

	case resp.StatusCode == 400 && c.provider == "Azure Blob":
		achado.Classificacao = "Conta existe (config/auth)"
		achado.Severidade = "INFO"

	default:
		// Status não indica nada acionável (ex: 3xx de redirecionamento
		// genérico) — não vale a pena reportar.
		return nil
	}

	if testarEscrita && !achado.TakeoverPossivel {
		testarEscritaBucket(ctx, client, c, achado)
	}

	return achado
}

// testarEscritaBucket tenta subir um arquivo de teste pequeno e, se
// conseguir, apaga em seguida. Só é chamado quando testarEscrita=true.
func testarEscritaBucket(ctx context.Context, client *http.Client, c candidato, achado *Achado) {
	nomeTeste := fmt.Sprintf("gorecon-permission-test-%d.txt", rand.Intn(1_000_000))
	urlTeste := strings.TrimSuffix(c.url, "/") + "/" + nomeTeste
	// Para Azure, a URL de container já tem query string — o objeto de
	// teste precisa ir antes do "?".
	if c.provider == "Azure Blob" {
		if i := strings.Index(c.url, "?"); i != -1 {
			urlTeste = c.url[:i] + "/" + nomeTeste
		}
	}

	corpo := strings.NewReader("gorecon-permission-check")
	reqCtx, cancel := context.WithTimeout(ctx, timeoutPorRequisicao)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPut, urlTeste, corpo)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		achado.CanWrite = true
		achado.Classificacao = "PÚBLICO COM ESCRITA (upload permitido)"
		achado.Severidade = "CRITICAL"

		// Limpa o arquivo de teste.
		delCtx, cancelDel := context.WithTimeout(ctx, timeoutPorRequisicao)
		defer cancelDel()
		delReq, err := http.NewRequestWithContext(delCtx, http.MethodDelete, urlTeste, nil)
		if err == nil {
			if delResp, err := client.Do(delReq); err == nil {
				delResp.Body.Close()
				if delResp.StatusCode >= 200 && delResp.StatusCode < 300 {
					achado.CanDelete = true
				}
			}
		}
	}
}

// CloudRecon extrai referências reais de storage em nuvem (S3, GCS, Azure
// Blob, DO Spaces, R2, Alibaba OSS) a partir do urls.txt e do JS já
// baixado pelo pipeline, e testa cada uma quanto a listagem pública,
// escrita e possibilidade de takeover — a mesma técnica usada pelo
// EnumRust, em vez de adivinhar nomes de bucket.
func CloudRecon(ctx context.Context, empresa string, testarEscrita bool) {
	fmt.Println("\n[+] Iniciando Cloud Recon (extração + teste de permissão)...")

	resultadosDir := filepath.Join(empresa, "resultados")
	if err := os.MkdirAll(resultadosDir, 0755); err != nil {
		fmt.Printf("[-] Erro criando diretório de resultados: %v\n", err)
		return
	}
	outputFile := filepath.Join(resultadosDir, "cloud-recon.json")

	candidatos := coletarCandidatos(resultadosDir)
	if len(candidatos) == 0 {
		fmt.Println("[-] Nenhuma referência de storage em nuvem encontrada em urls.txt/javascripts/. Nada a testar.")
		os.WriteFile(outputFile, []byte("[]"), 0644)
		return
	}
	fmt.Printf("[*] %d referência(s) de bucket extraída(s) do recon já coletado. Testando permissões...\n", len(candidatos))
	if testarEscrita {
		fmt.Println("[!] Teste de escrita ATIVADO — o GoRecon vai tentar subir e apagar um arquivo de teste em buckets públicos.")
	}

	client := &http.Client{Timeout: timeoutPorRequisicao}

	var (
		mu      sync.Mutex
		achados []Achado
	)
	sem := make(chan struct{}, concorrencia)
	var wg sync.WaitGroup
	cancelado := false

loopCandidatos:
	for _, c := range candidatos {
		select {
		case <-ctx.Done():
			cancelado = true
			break loopCandidatos
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(c candidato) {
			defer wg.Done()
			defer func() { <-sem }()

			achado := testarPermissoes(ctx, client, c, testarEscrita)
			if achado == nil {
				return
			}
			mu.Lock()
			achados = append(achados, *achado)
			mu.Unlock()
			fmt.Printf("[+] [%s] %s: %s (HTTP %d, fonte: %s)\n", achado.Severidade, c.provider, c.bucket, achado.StatusCode, c.fonte)
		}(c)
	}
	wg.Wait()

	if cancelado {
		fmt.Println("\n[!] Cloud Recon cancelado pelo usuário (CTRL + C).")
	}

	sort.Slice(achados, func(i, j int) bool {
		ordem := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
		if ordem[achados[i].Severidade] != ordem[achados[j].Severidade] {
			return ordem[achados[i].Severidade] < ordem[achados[j].Severidade]
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

	fmt.Printf("[+] Cloud Recon finalizado: %d achado(s) relevante(s) salvos em %s\n", len(achados), outputFile)
}
