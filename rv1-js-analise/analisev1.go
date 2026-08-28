package rv1jsanalise

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Módulo de análise de JavaScript (fase de download + extração + segredos).
//
// Fluxo (espelhando o teste.sh / Recon5):
//
//   js/urls.txt (fila priorizada)
//        ↓  BaixarJS (seletivo, concorrente)
//   js/downloaded/<sha1>.js
//        ↓  ExtrairEndpoints (multi-ferramenta: jsluice + jshunter + linkfinder)
//   js/sources.jsonl          (endpoints com proveniência)
//        ↓  agregação
//   js/endpoints.txt, js/endpoints_full.txt, api/endpoints.txt, api/graphql.txt,
//   js/js_parameters.txt
//        ↓  ValidarEndpoints (httpx direcionado)
//   api/endpoints_probed.txt
//        ↓  AnalisarSegredos (trufflehog + gitleaks + secretfinder)
//   js/secrets.txt
// ---------------------------------------------------------------------------

const (
	concBaixarJS  = 10       // downloads paralelos
	timeoutReqSec = 20       // timeout por requisição HTTP
	maxFileBytes  = 26214400 // 25 MB por arquivo JS
)

// Fonte representa um endpoint extraído com sua proveniência.
type Fonte struct {
	Endpoint string `json:"endpoint"`
	Source   string `json:"source"` // URL do JS de origem
	Tool     string `json:"tool"`   // jsluice | jshunter | linkfinder | native
	Scope    bool   `json:"scope"`
	Tier     string `json:"tier"`
	Resolved bool   `json:"resolved"`
}

// hasTool informa se um binário está disponível no PATH.
func hasTool(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func fileExiste(caminho string) bool {
	_, err := os.Stat(caminho)
	return err == nil
}

// ---------------------------------------------------------------------------
// BaixarJS — download seletivo e concorrente dos JS priorizados
// ---------------------------------------------------------------------------

// BaixarJS baixa os JS de js/urls.txt (fila já priorizada) para js/downloaded/.
// Usa worker pool com concorrência controlada, timeout e limite de tamanho.
func BaixarJS(ctx context.Context, empresa string) {
	fmt.Println("[+] Baixando arquivos JavaScript (seletivo, concorrente)...")

	resultadosDir := filepath.Join(empresa, "resultados")
	jsDir := filepath.Join(resultadosDir, "js")
	inputJS := filepath.Join(jsDir, "urls.txt")
	downloadDir := filepath.Join(jsDir, "downloaded")

	if !fileExiste(inputJS) {
		fmt.Println("[-] js/urls.txt não encontrado — rode a priorização antes.")
		return
	}
	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		fmt.Printf("[-] Erro criando diretório de download: %v\n", err)
		return
	}

	arquivo, err := os.Open(inputJS)
	if err != nil {
		fmt.Printf("[-] Erro ao abrir %s: %v\n", inputJS, err)
		return
	}

	var urls []string
	scanner := bufio.NewScanner(arquivo)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		linha := strings.TrimSpace(scanner.Text())
		if linha != "" {
			urls = append(urls, linha)
		}
	}
	arquivo.Close()
	if err := scanner.Err(); err != nil {
		fmt.Printf("[-] Erro lendo %s: %v\n", inputJS, err)
		return
	}
	if len(urls) == 0 {
		fmt.Println("[-] Nenhum JS na fila de download.")
		return
	}

	client := &http.Client{Timeout: timeoutReqSec * time.Second}

	sem := make(chan struct{}, concBaixarJS)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var baixados, falhas int

	for _, u := range urls {
		select {
		case <-ctx.Done():
			wg.Wait()
			fmt.Printf("[!] Download cancelado: %d baixados, %d falhas.\n", baixados, falhas)
			return
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			destino := filepath.Join(downloadDir, hashURL(u)+".js")
			if err := baixarArquivo(ctx, client, u, destino); err != nil {
				mu.Lock()
				falhas++
				mu.Unlock()
				return
			}
			mu.Lock()
			baixados++
			mu.Unlock()
		}(u)
	}
	wg.Wait()

	fmt.Printf("[+] %d arquivos JS baixados em %s (%d falhas).\n", baixados, downloadDir, falhas)
}

func hashURL(u string) string {
	soma := sha1.Sum([]byte(u))
	return hex.EncodeToString(soma[:])
}

func baixarArquivo(ctx context.Context, client *http.Client, u, destino string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status HTTP %d", resp.StatusCode)
	}

	out, err := os.Create(destino)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, io.LimitReader(resp.Body, maxFileBytes))
	closeErr := out.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// ---------------------------------------------------------------------------
// ExtrairEndpoints — extração multi-ferramenta com proveniência
// ---------------------------------------------------------------------------

// ExtrairEndpoints roda, para cada JS baixado, os extratores disponíveis
// (jsluice, jshunter, linkfinder e um fallback nativo), filtra o resultado
// pelos domínios/subdomínios de arquivoAlvos (descarta ruído de terceiros:
// CDNs, analytics, plugins de terceiros, etc.) e agrega tudo em
// js/sources.jsonl + os arquivos consolidados de endpoints.
func ExtrairEndpoints(ctx context.Context, arquivoAlvos, empresa string) {
	fmt.Println("[+] Extraindo endpoints dos JS (jsluice + jshunter + linkfinder)...")

	resultadosDir := filepath.Join(empresa, "resultados")
	jsDir := filepath.Join(resultadosDir, "js")
	downloadDir := filepath.Join(jsDir, "downloaded")

	entradas, err := os.ReadDir(downloadDir)
	if err != nil || len(entradas) == 0 {
		fmt.Println("[-] Nenhum JS baixado. Rode BaixarJS antes.")
		return
	}

	// Domínios-alvo (de Alvos.txt) usados para filtrar o que é ruído de
	// terceiros do que realmente pertence ao escopo. Se o arquivo não puder
	// ser lido, o filtro é desativado (mantém tudo) em vez de zerar a saída.
	dominiosAlvo := carregarDominiosAlvo(arquivoAlvos)
	if len(dominiosAlvo) == 0 {
		fmt.Printf("[!] Não foi possível carregar domínios de %s — filtro de escopo desativado (todos os endpoints serão mantidos).\n", arquivoAlvos)
	}

	// Mapa sha1 -> URL de origem (para associar a proveniência).
	origem := montarMapaOrigem(filepath.Join(jsDir, "urls.txt"))

	var mu sync.Mutex
	fontes := make([]Fonte, 0, 4096)

	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup

	for _, e := range entradas {
		if e.IsDir() {
			continue
		}
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(nome string) {
			defer wg.Done()
			defer func() { <-sem }()

			hash := strings.TrimSuffix(nome, ".js")
			srcURL := origem[hash]
			if srcURL == "" {
				// Fallback: reconstrói a URL não mapeada como arquivo local.
				srcURL = "file:" + nome
			}
			conteudo, err := os.ReadFile(filepath.Join(downloadDir, nome))
			if err != nil {
				return
			}

			locals := extrairDeUmJS(ctx, srcURL, conteudo)
			mu.Lock()
			fontes = append(fontes, locals...)
			mu.Unlock()
		}(e.Name())
	}
	wg.Wait()

	// CORREÇÃO: Scope não era mais calculado de verdade (sempre "true"), o
	// que deixava passar qualquer domínio de terceiro (CDN, analytics,
	// plugins como yoast.com, x.com/twitter, etc.) direto pro painel.
	// Agora cada endpoint é comparado contra os domínios/subdomínios de
	// Alvos.txt; só o que está em escopo vai para os arquivos consolidados
	// e para o painel — o resto fica registrado em js/fora_de_escopo.jsonl
	// para auditoria, sem sumir silenciosamente.
	marcarEscopo(fontes, dominiosAlvo)
	escopo, foraDeEscopo := separarPorEscopo(fontes)

	sort.Slice(escopo, func(i, j int) bool { return escopo[i].Endpoint < escopo[j].Endpoint })
	sort.Slice(foraDeEscopo, func(i, j int) bool { return foraDeEscopo[i].Endpoint < foraDeEscopo[j].Endpoint })

	salvarFontes(filepath.Join(jsDir, "sources.jsonl"), escopo)
	agregarEndpoints(resultadosDir, escopo)
	if len(foraDeEscopo) > 0 {
		salvarFontes(filepath.Join(jsDir, "fora_de_escopo.jsonl"), foraDeEscopo)
	}

	fmt.Printf("[+] Endpoints extraídos: %d em escopo (js/sources.jsonl), %d fora de escopo descartados (js/fora_de_escopo.jsonl).\n", len(escopo), len(foraDeEscopo))
}

// carregarDominiosAlvo lê Alvos.txt (um domínio raiz por linha, aceita
// "*.exemplo.com" e ignora linhas vazias/comentários) e devolve a lista
// normalizada em minúsculas.
func carregarDominiosAlvo(caminho string) []string {
	f, err := os.Open(caminho)
	if err != nil {
		return nil
	}
	defer f.Close()

	var dominios []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		d := strings.ToLower(strings.TrimSpace(sc.Text()))
		d = strings.TrimPrefix(d, "*.")
		if d == "" || strings.HasPrefix(d, "#") {
			continue
		}
		dominios = append(dominios, d)
	}
	if err := sc.Err(); err != nil {
		fmt.Printf("[-] Erro lendo %s: %v\n", caminho, err)
	}
	return dominios
}

// emEscopo confere se host é igual a um domínio-alvo ou um subdomínio dele
// (ex: "j1visa.state.gov" está em escopo de "state.gov"; "esri.com" não).
func emEscopo(host string, dominios []string) bool {
	host = strings.ToLower(host)
	for _, d := range dominios {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// marcarEscopo recalcula o campo Scope de cada Fonte com base no host real
// do endpoint. Se dominios estiver vazio (Alvos.txt ilegível), não mexe em
// nada — mantém o comportamento anterior (tudo em escopo) em vez de
// derrubar a saída inteira por um problema de leitura de arquivo.
func marcarEscopo(fontes []Fonte, dominios []string) {
	if len(dominios) == 0 {
		return
	}
	for i := range fontes {
		host := ""
		if u, err := url.Parse(fontes[i].Endpoint); err == nil {
			host = u.Hostname()
		}
		fontes[i].Scope = emEscopo(host, dominios)
	}
}

// separarPorEscopo divide as fontes entre em-escopo e fora-de-escopo,
// preservando a ordem relativa.
func separarPorEscopo(fontes []Fonte) (escopo, foraDeEscopo []Fonte) {
	for _, f := range fontes {
		if f.Scope {
			escopo = append(escopo, f)
		} else {
			foraDeEscopo = append(foraDeEscopo, f)
		}
	}
	return
}

// montarMapaOrigem lê js/urls.txt e devolve sha1(url) -> url.
func montarMapaOrigem(urlsPath string) map[string]string {
	mapa := make(map[string]string)
	if !fileExiste(urlsPath) {
		return mapa
	}
	f, err := os.Open(urlsPath)
	if err != nil {
		return mapa
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		u := strings.TrimSpace(scanner.Text())
		if u != "" {
			mapa[hashURL(u)] = u
		}
	}
	// CORREÇÃO: erro do scanner agora é reportado em vez de ser ignorado.
	if err := scanner.Err(); err != nil {
		fmt.Printf("[-] Erro lendo %s: %v\n", urlsPath, err)
	}
	return mapa
}

// extrairDeUmJS roda os extratores sobre o conteúdo de um único JS.
func extrairDeUmJS(ctx context.Context, srcURL string, conteudo []byte) []Fonte {
	visto := make(map[string]struct{})
	var out []Fonte

	adicionar := func(endpoint, tool string) {
		endpoint = normalizarEndpoint(endpoint, srcURL)
		if endpoint == "" {
			return
		}
		if _, ok := visto[endpoint]; ok {
			return
		}
		visto[endpoint] = struct{}{}
		out = append(out, Fonte{
			Endpoint: endpoint,
			Source:   srcURL,
			Tool:     tool,
			Scope:    true,
			Tier:     tierDaURL(srcURL),
			Resolved: true,
		})
	}

	// 1. jsluice (AST, preferencial — resolve concatenação/ofuscação).
	if hasTool("jsluice") {
		cmd := exec.CommandContext(ctx, "jsluice", "urls", "-")
		cmd.Stdin = strings.NewReader(string(conteudo))
		outBytes, err := cmd.Output()
		if err == nil {
			linhas := strings.Split(string(outBytes), "\n")
			for _, linha := range linhas {
				linha = strings.TrimSpace(linha)
				if linha == "" || !strings.HasPrefix(linha, "{") {
					continue
				}
				var obj struct {
					URL string `json:"url"`
				}
				if json.Unmarshal([]byte(linha), &obj) == nil && obj.URL != "" {
					adicionar(obj.URL, "jsluice")
				}
			}
		}
	}

	// 2. jshunter (endpoints de texto).
	if hasTool("jshunter") {
		tmp, err := os.CreateTemp("", "jshunter-*.js")
		if err == nil {
			tmp.Write(conteudo)
			tmpPath := tmp.Name()
			tmp.Close()
			defer os.Remove(tmpPath)

			cmd := exec.CommandContext(ctx, "jshunter", tmpPath, "-ep", "-q")
			outBytes, _ := cmd.Output()
			for _, linha := range strings.Split(string(outBytes), "\n") {
				linha = strings.TrimSpace(linha)
				if strings.HasPrefix(linha, "ENDPOINT:") {
					adicionar(strings.TrimSpace(strings.TrimPrefix(linha, "ENDPOINT:")), "jshunter")
				} else if strings.HasPrefix(linha, "URL:") {
					adicionar(strings.TrimSpace(strings.TrimPrefix(linha, "URL:")), "jshunter")
				}
			}
		}
	}

	// 3. linkfinder (regex agressiva).
	if hasTool("linkfinder") {
		tmp, err := os.CreateTemp("", "linkfinder-*.js")
		if err == nil {
			tmp.Write(conteudo)
			tmpPath := tmp.Name()
			tmp.Close()
			defer os.Remove(tmpPath)

			cmd := exec.CommandContext(ctx, "python3", buscarLinkFinder(), "-i", tmpPath, "-o", "cli")
			outBytes, _ := cmd.Output()
			for _, linha := range strings.Split(string(outBytes), "\n") {
				linha = strings.TrimSpace(linha)
				linha = strings.Trim(linha, `"'`)
				if linha != "" {
					adicionar(linha, "linkfinder")
				}
			}
		}
	}

	// 4. Fallback nativo (regex simples) — garante saída mesmo sem ferramentas.
	for _, ep := range extrairNativoFallback(conteudo, srcURL) {
		adicionar(ep, "native")
	}

	return out
}

// buscarLinkFinder localiza o linkfinder.py nos caminhos comuns.
func buscarLinkFinder() string {
	candidatos := []string{
		"/opt/LinkFinder/linkfinder.py",
		"/usr/local/LinkFinder/linkfinder.py",
		"/home/ubuntu/LinkFinder/linkfinder.py",
		"/root/LinkFinder/linkfinder.py",
		"/home/ubuntu/Download/LinkFinder/linkfinder.py",
	}
	for _, c := range candidatos {
		if fileExiste(c) {
			return c
		}
	}
	return "linkfinder.py"
}

// tierDaURL tenta inferir o tier do JS a partir do js/to_download.tsv.
// TODO: ainda não implementado (sempre retorna "LOW"); o parâmetro é
// mantido para quando essa lookup for implementada, por isso o "_"
// silencia o aviso de parâmetro não usado sem mudar a assinatura pública.
func tierDaURL(_ string) string {
	return "LOW"
}

// ---------------------------------------------------------------------------
// Agregação
// ---------------------------------------------------------------------------

// salvarFontes escreve as fontes em JSONL.
func salvarFontes(caminho string, fontes []Fonte) {
	f, err := os.Create(caminho)
	if err != nil {
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, src := range fontes {
		b, _ := json.Marshal(src)
		w.Write(b)
		w.WriteString("\n")
	}
	w.Flush()
}

// agregarEndpoints consolida js/sources.jsonl nos arquivos de saída:
//
//	js/endpoints.txt, js/endpoints_full.txt, js/domains.txt,
//	api/endpoints.txt, api/graphql.txt, js/js_parameters.txt
func agregarEndpoints(resultadosDir string, fontes []Fonte) {
	jsDir := filepath.Join(resultadosDir, "js")
	apiDir := filepath.Join(resultadosDir, "api")
	os.MkdirAll(apiDir, 0755)

	// Dedup canônica por endpoint (esquema/porta normalizados).
	todos := make(map[string]Fonte)
	for _, f := range fontes {
		chave := chaveCanonica(f.Endpoint)
		if _, ok := todos[chave]; !ok {
			todos[chave] = f
		}
	}

	var endpoints, endpointsFull, domains, apis, graphqls, params []string
	for _, f := range todos {
		endpoints = append(endpoints, f.Endpoint)
		endpointsFull = append(endpointsFull, f.Endpoint+"\t"+f.Tool+"\t"+f.Source)

		if u, err := url.Parse(f.Endpoint); err == nil && u.Host != "" {
			domains = append(domains, u.Host)
		}

		low := strings.ToLower(f.Endpoint)
		if ehGraphQL(low) {
			graphqls = append(graphqls, f.Endpoint)
		}
		if ehAPI(low) {
			apis = append(apis, f.Endpoint)
		}
		for _, p := range extrairParametros(f.Endpoint) {
			params = append(params, p)
		}
	}

	sort.Strings(endpoints)
	sort.Strings(domains)
	sort.Strings(apis)
	sort.Strings(graphqls)
	sort.Strings(params)

	escreverLinhas(filepath.Join(jsDir, "endpoints.txt"), endpoints)
	escreverLinhas(filepath.Join(jsDir, "endpoints_full.txt"), endpointsFull)
	escreverLinhas(filepath.Join(jsDir, "domains.txt"), domains)

	// api/endpoints.txt e api/graphql.txt acumulam com o que já existia de crawl.
	acumularLinhas(filepath.Join(apiDir, "endpoints.txt"), apis)
	acumularLinhas(filepath.Join(apiDir, "graphql.txt"), graphqls)
	escreverLinhas(filepath.Join(jsDir, "js_parameters.txt"), params)
}

func escreverLinhas(caminho string, linhas []string) {
	f, err := os.Create(caminho)
	if err != nil {
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, l := range linhas {
		w.WriteString(l)
		w.WriteString("\n")
	}
	w.Flush()
}

func acumularLinhas(caminho string, linhas []string) {
	existentes := make(map[string]struct{})
	if f, err := os.Open(caminho); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			existentes[strings.TrimSpace(sc.Text())] = struct{}{}
		}
		// CORREÇÃO: erro do scanner agora é reportado em vez de ser ignorado.
		if err := sc.Err(); err != nil {
			fmt.Printf("[-] Erro lendo %s: %v\n", caminho, err)
		}
		f.Close()
	}
	f, err := os.OpenFile(caminho, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, l := range linhas {
		if _, ok := existentes[l]; ok {
			continue
		}
		existentes[l] = struct{}{}
		w.WriteString(l)
		w.WriteString("\n")
	}
	w.Flush()
}

func ehGraphQL(low string) bool {
	return strings.Contains(low, "graphql") || strings.Contains(low, "graphiql") || strings.Contains(low, "/gql") || strings.Contains(low, "/query")
}

func ehAPI(low string) bool {
	return strings.Contains(low, "/api/") || strings.Contains(low, "/v1/") || strings.Contains(low, "/v2/") ||
		strings.Contains(low, "/rest/") || strings.Contains(low, "/graphql") || strings.HasSuffix(low, "/api")
}

func extrairParametros(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	var out []string
	for nome := range u.Query() {
		out = append(out, nome)
	}
	return out
}

func chaveCanonica(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	// remove porta default
	host = strings.TrimSuffix(host, ":80")
	host = strings.TrimSuffix(host, ":443")
	if scheme == "http" {
		scheme = "http"
	}
	if scheme == "" {
		scheme = "http"
	}
	u.Scheme = scheme
	u.Host = host
	u.Fragment = ""
	return u.String()
}

// normalizarEndpoint limpa e resolve um endpoint contra a URL de origem.
func normalizarEndpoint(raw, srcURL string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, "\"',;")
	if raw == "" {
		return ""
	}

	// Concatenações que sobraram: "VAR + /path" já resolvidas pelas ferramentas.
	base, err := url.Parse(srcURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
			return raw
		}
		return ""
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	resolvido := base.ResolveReference(ref)
	if resolvido.Scheme != "http" && resolvido.Scheme != "https" {
		return ""
	}
	resolvido.Fragment = ""
	return resolvido.String()
}

// ---------------------------------------------------------------------------
// Fallback nativo (regex simples) para quando as ferramentas externas faltam
// ---------------------------------------------------------------------------

// CORREÇÃO: a classe de caracteres incluía aspas simples ('), que também
// delimitam strings em JS. Isso fazia o regex "atravessar" o fim de uma
// string JS de URL e continuar grudando o próximo literal concatenado
// (ex: 'https://www.esri.com'+'mailto'+'email' virava
// "https://www.esri.commailtoemail"). Sem o ' na classe, o match para
// corretamente no fechamento da string.
var regexURLLiteral = mustCompile(`(?i)https?://[a-zA-Z0-9._~:\-\[\]@!$&()*+,;=%/?]+`)
var regexPathAbs = mustCompile(`["'](/[A-Za-z0-9._~\-!$&'()*+,;=:@/]{2,})["']`)

func mustCompile(expr string) *regexp.Regexp {
	return regexp.MustCompile(expr)
}

func extrairNativoFallback(conteudo []byte, _ string) []string {
	texto := string(conteudo)
	visto := make(map[string]struct{})
	var out []string
	for _, m := range regexURLLiteral.FindAllString(texto, -1) {
		if _, ok := visto[m]; !ok {
			visto[m] = struct{}{}
			out = append(out, m)
		}
	}
	for _, m := range regexPathAbs.FindAllStringSubmatch(texto, -1) {
		if len(m) > 1 && strings.Contains(m[1], "/") {
			if _, ok := visto[m[1]]; !ok {
				visto[m[1]] = struct{}{}
				out = append(out, m[1])
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// ValidarEndpoints — validação HTTP direcionada
// ---------------------------------------------------------------------------

// ValidarEndpoints roda httpx sobre api/endpoints.txt + api/graphql.txt,
// aceitando os status indicativos de "endpoint existe", e grava
// api/endpoints_probed.txt.
func ValidarEndpoints(ctx context.Context, empresa string) {
	fmt.Println("[+] Validando endpoints extraídos (httpx direcionado)...")

	resultadosDir := filepath.Join(empresa, "resultados")
	apiDir := filepath.Join(resultadosDir, "api")
	targets := filepath.Join(apiDir, ".probe_targets.tmp")

	// Junta endpoints e graphql num arquivo temporário.
	var linhas []string
	for _, nome := range []string{"endpoints.txt", "graphql.txt"} {
		p := filepath.Join(apiDir, nome)
		if !fileExiste(p) {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if l := strings.TrimSpace(sc.Text()); l != "" {
				linhas = append(linhas, l)
			}
		}
		// CORREÇÃO: erro do scanner agora é reportado em vez de ser ignorado.
		if err := sc.Err(); err != nil {
			fmt.Printf("[-] Erro lendo %s: %v\n", p, err)
		}
		f.Close()
	}
	if len(linhas) == 0 {
		fmt.Println("[-] Nenhum endpoint para validar.")
		return
	}
	sort.Strings(linhas)
	escreverLinhas(targets, linhas)
	defer os.Remove(targets)

	if !hasTool("httpx") {
		fmt.Println("[!] httpx não encontrado — validação de endpoints pulada.")
		return
	}

	outPath := filepath.Join(apiDir, "endpoints_probed.txt")
	outFile, err := os.Create(outPath)
	if err != nil {
		return
	}
	defer outFile.Close()

	cmd := exec.CommandContext(ctx, "httpx",
		"-l", targets,
		"-silent",
		"-timeout", "8",
		"-sc", "-cl", "-title", "-td",
		"-mc", "200,201,204,301,302,401,403,405,500",
	)
	cmd.Stdout = outFile
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.Canceled {
			fmt.Println("[!] Validação de endpoints cancelada.")
			return
		}
		fmt.Printf("[-] httpx terminou com erro: %v\n", err)
		return
	}

	contagem, _ := countLines(outPath)
	fmt.Printf("[+] Endpoints responsivos: %d (api/endpoints_probed.txt)\n", contagem)
}

func countLines(caminho string) (int, error) {
	f, err := os.Open(caminho)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		n++
	}
	return n, sc.Err()
}

// ---------------------------------------------------------------------------
// AnalisarSegredos — trufflehog + gitleaks + secretfinder
// ---------------------------------------------------------------------------

// AnalisarSegredos roda trufflehog (primário) e gitleaks (fallback) sobre os
// JS baixados, consolidando resultados legíveis em js/secrets.txt.
func AnalisarSegredos(ctx context.Context, empresa string) {
	fmt.Println("[+] Buscando segredos nos JS (trufflehog + gitleaks)...")

	resultadosDir := filepath.Join(empresa, "resultados")
	jsDir := filepath.Join(resultadosDir, "js")
	downloadDir := filepath.Join(jsDir, "downloaded")

	entradas, err := os.ReadDir(downloadDir)
	if err != nil || len(entradas) == 0 {
		fmt.Println("[-] Nenhum JS baixado para escanear.")
		return
	}

	var linhas []string

	if hasTool("trufflehog") {
		cmd := exec.CommandContext(ctx, "trufflehog", "filesystem", downloadDir, "--no-update")
		if out, err := cmd.Output(); err == nil {
			linhas = append(linhas, "# trufflehog")
			linhas = append(linhas, string(out))
		} else if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) > 0 {
			linhas = append(linhas, string(exitErr.Stderr))
		}
	} else {
		fmt.Println("[!] trufflehog não encontrado.")
	}

	if hasTool("gitleaks") {
		cmd := exec.CommandContext(ctx, "gitleaks", "detect", "--source", downloadDir, "--no-banner", "--report-format", "json")
		if out, err := cmd.Output(); err == nil {
			linhas = append(linhas, "# gitleaks")
			var achados []map[string]interface{}
			if json.Unmarshal(out, &achados) == nil {
				for _, a := range achados {
					if desc, ok := a["Description"].(string); ok {
						linhas = append(linhas, desc)
					}
				}
			} else {
				linhas = append(linhas, string(out))
			}
		}
	} else {
		fmt.Println("[!] gitleaks não encontrado.")
	}

	escreverLinhas(filepath.Join(jsDir, "secrets.txt"), linhas)
	fmt.Printf("[+] Análise de segredos concluída: %d linhas (js/secrets.txt).\n", len(linhas))
}
