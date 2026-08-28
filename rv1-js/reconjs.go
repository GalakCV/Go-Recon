package rv1js

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Módulo de reconhecimento de JavaScript (fase de descoberta + priorização).
//
// Coleta candidatos .js a partir de:
//   - katana (crawl atual)                    -> fonte "crawl"
//   - gau / waymore / xnLinkFinder (histórico)-> fonte "historical"
//   - subjs (descoberta de JS por fontes)     -> fonte "crawl"
//   - getJS (descoberta de JS)                -> fonte "historical"
//
// Depois prioriza em tiers HIGH/MEDIUM/LOW/SKIP, replicando o comportamento
// do teste.sh (js-priority): arquivos de terceiros (analytics/CDN/vendor)
// viram SKIP e nunca são baixados.
// ---------------------------------------------------------------------------

const tamanhoMaximoScanner = 1024 * 1024

// tempoMaximoKatana é o teto de segurança para a etapa de crawl do katana.
// Além das flags internas do katana (-crawl-duration), este timeout garante
// que a etapa nunca fique presa indefinidamente, mesmo que o katana ignore
// suas próprias flags ou fique preso numa página problemática.
const tempoMaximoKatana = 15 * time.Minute

// palavrasTerceiros identifica hosts de analytics/CDN/vendor que devem virar
// SKIP na priorização (mesmo espírito do js/third_party.txt do teste.sh).
var palavrasTerceiros = []string{
	"google-analytics", "googletagmanager", "doubleclick", "facebook", "fbq",
	"hotjar", "segment.com", "mixpanel", "amplitude", "intercom", "zendesk",
	"cloudflare", "cloudfront", "jsdelivr", "cdnjs", "unpkg", "bootstrapcdn",
	"ajax.googleapis", "maps.googleapis", "googlesyndication", "adsbygoogle",
	"newrelic", "fullstory", "sentry", "bugsnag", "mouseflow", "luckyorange",
	"hubspot", "marketo", "pardot", "salesforce", "crisp", "tawk", "drift",
	"onesignal", "pusher", "stripe.com", "paypal", "recaptcha", "hcaptcha",
	"turnstile", "captcha-delivery", "challenge-platform", "cookiebot",
	"onetrust", "consent", "cookieyes", "usercentrics", "quantcast",
	"scorecardresearch", "addthis", "sharethis", "youtube", "ytimg",
	"vimeo", "twimg", "googlevideo", "licdn", "gravatar", "typekit",
}

// hasTool informa se um binário externo está disponível no PATH.
func hasTool(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func fileExiste(caminho string) bool {
	_, err := os.Stat(caminho)
	return err == nil
}

// ColetarJS descobre candidatos .js de fontes atuais e históricas e grava
// js/candidates.tsv (url<TAB>fonte).
func ColetarJS(ctx context.Context, empresa string) {
	fmt.Println("[+] Coletando candidatos JavaScript (katana + fontes históricas)...")

	resultadosDir := filepath.Join(empresa, "resultados")
	jsDir := filepath.Join(resultadosDir, "js")
	if err := os.MkdirAll(jsDir, 0755); err != nil {
		fmt.Printf("[-] Erro criando diretório JS: %v\n", err)
		return
	}

	candidatos := make(map[string]string) // url -> fonte (crawl/historical)

	status200 := filepath.Join(resultadosDir, "status200.txt")

	// 1. katana — crawl atual, fonte "crawl".
	if hasTool("katana") && fileExiste(status200) {
		coletarKatana(ctx, status200, candidatos)
	} else {
		fmt.Println("[!] katana não encontrado ou status200.txt ausente (crawl atual pulado).")
	}

	// 2. fontes históricas salvas por rv1-crawling (gau/waymore/xnLinkFinder).
	historicos := []struct {
		arquivo string
		fonte   string
	}{
		{"gau.txt", "historical"},
		{"waymore.txt", "historical"},
		{"xnlinkfinder.txt", "historical"},
		{"urls.txt", "historical"},
	}
	for _, h := range historicos {
		p := filepath.Join(resultadosDir, h.arquivo)
		if fileExiste(p) {
			coletarDeArquivo(p, h.fonte, candidatos)
		}
	}

	// 3. subjs — mesma origem que o alvo, fonte "crawl".
	if hasTool("subjs") && fileExiste(status200) {
		coletarSubjs(ctx, status200, candidatos)
	}

	// 4. getJS — descoberta complementar de JS, fonte "historical".
	urlsTxt := filepath.Join(resultadosDir, "urls.txt")
	if hasTool("getJS") && fileExiste(urlsTxt) {
		coletarGetJS(ctx, urlsTxt, candidatos)
	}

	escreverCandidates(jsDir, candidatos)
	fmt.Printf("[+] Candidatos JS coletados: %d (js/candidates.tsv)\n", len(candidatos))
}

// PriorizarJS lê js/candidates.tsv, classifica cada URL em tier e grava:
//   js/priority.tsv     -> url<TAB>fonte<TAB>tier
//   js/third_party.txt  -> URLs SKIP (nunca baixadas)
//   js/to_download.tsv  -> fila de download (>= cutoff)
//   js/urls.txt         -> somente URLs da fila (compatibilidade)
func PriorizarJS(ctx context.Context, empresa string) {
	fmt.Println("[+] Priorizando JavaScript (tiers HIGH/MEDIUM/LOW/SKIP)...")

	resultadosDir := filepath.Join(empresa, "resultados")
	jsDir := filepath.Join(resultadosDir, "js")
	candTsv := filepath.Join(jsDir, "candidates.tsv")

	if !fileExiste(candTsv) {
		fmt.Println("[-] js/candidates.tsv não encontrado — rode a coleta antes.")
		return
	}

	arquivo, err := os.Open(candTsv)
	if err != nil {
		fmt.Printf("[-] Erro ao abrir candidates.tsv: %v\n", err)
		return
	}
	defer arquivo.Close()

	type candidato struct {
		url   string
		fonte string
		tier  string
	}

	var lista []candidato
	scanner := bufio.NewScanner(arquivo)
	scanner.Buffer(make([]byte, 64*1024), tamanhoMaximoScanner)
	for scanner.Scan() {
		linha := strings.TrimSpace(scanner.Text())
		if linha == "" {
			continue
		}
		partes := strings.SplitN(linha, "\t", 2)
		u := partes[0]
		fonte := "historical"
		if len(partes) == 2 {
			fonte = partes[1]
		}
		host, caminho := caminhoECaminho(u)
		tier := classificarTier(host, caminho, fonte)
		lista = append(lista, candidato{url: u, fonte: fonte, tier: tier})
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("[-] Erro lendo candidates.tsv: %v\n", err)
		return
	}

	sort.Slice(lista, func(i, j int) bool { return lista[i].url < lista[j].url })

	rankTier := map[string]int{"HIGH": 3, "MEDIUM": 2, "LOW": 1, "SKIP": 0}
	cutoff := rankTier["LOW"]

	priorityPath := filepath.Join(jsDir, "priority.tsv")
	thirdPath := filepath.Join(jsDir, "third_party.txt")
	toDownloadPath := filepath.Join(jsDir, "to_download.tsv")
	urlsPath := filepath.Join(jsDir, "urls.txt")

	fPriority, _ := os.Create(priorityPath)
	defer fPriority.Close()
	fThird, _ := os.Create(thirdPath)
	defer fThird.Close()
	fDownload, _ := os.Create(toDownloadPath)
	defer fDownload.Close()
	fURLs, _ := os.Create(urlsPath)
	defer fURLs.Close()

	wPriority := bufio.NewWriter(fPriority)
	wThird := bufio.NewWriter(fThird)
	wDownload := bufio.NewWriter(fDownload)
	wURLs := bufio.NewWriter(fURLs)

	var nAlta, nMedia, nBaixa, nSkip int
	for _, c := range lista {
		fmt.Fprintf(wPriority, "%s\t%s\t%s\n", c.url, c.fonte, c.tier)
		if c.tier == "SKIP" {
			wThird.WriteString(c.url)
			wThird.WriteString("\n")
			nSkip++
			continue
		}
		if rankTier[c.tier] >= cutoff {
			fmt.Fprintf(wDownload, "%s\t%s\t%s\n", c.url, c.fonte, c.tier)
			wURLs.WriteString(c.url)
			wURLs.WriteString("\n")
		}
		switch c.tier {
		case "HIGH":
			nAlta++
		case "MEDIUM":
			nMedia++
		case "LOW":
			nBaixa++
		}
	}

	wPriority.Flush()
	wThird.Flush()
	wDownload.Flush()
	wURLs.Flush()

	fmt.Printf("[+] Priorização: HIGH=%d MEDIUM=%d LOW=%d SKIP=%d\n", nAlta, nMedia, nBaixa, nSkip)
}

// ---------------------------------------------------------------------------
// Coletores
// ---------------------------------------------------------------------------

func coletarKatana(ctx context.Context, status200 string, dest map[string]string) {
	// CORREÇÃO: sem limites o katana crawlava com profundidade/concorrência
	// padrão e SEM teto de tempo — em listas grandes de hosts (status200.txt)
	// isso podia rodar por horas. Agora limitamos profundidade, concorrência,
	// timeout por requisição e, principalmente, um teto de duração total
	// (-crawl-duration) para que a etapa sempre termine sozinha.
	kctx, cancel := context.WithTimeout(ctx, tempoMaximoKatana)
	defer cancel()

	cmd := exec.CommandContext(kctx, "katana",
		"-list", status200,
		"-jc",
		"-silent",
		"-d", "2", // profundidade máxima de crawl
		"-c", "20", // concorrência (goroutines)
		"-p", "20", // paralelismo (hosts simultâneos)
		"-timeout", "10", // timeout por requisição, em segundos
		"-crawl-duration", "10m", // teto de duração total do crawl
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Printf("[-] Erro criando pipe do katana: %v\n", err)
		return
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Printf("[-] Erro iniciando katana: %v\n", err)
		return
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), tamanhoMaximoScanner)
	for scanner.Scan() {
		if kctx.Err() != nil {
			break
		}
		adicionarCandidato(dest, strings.TrimSpace(scanner.Text()), "crawl")
	}
	// CORREÇÃO: erro do scanner (ex: linha maior que o buffer) agora é
	// reportado em vez de ser silenciosamente ignorado.
	if err := scanner.Err(); err != nil {
		fmt.Printf("[-] Erro lendo saída do katana: %v\n", err)
	}
	if err := cmd.Wait(); err != nil && kctx.Err() == context.DeadlineExceeded {
		fmt.Println("[!] katana atingiu o teto de 10 minutos de crawl e foi encerrado.")
	}
}

func coletarSubjs(ctx context.Context, status200 string, dest map[string]string) {
	entries, err := os.ReadFile(status200)
	if err != nil {
		return
	}
	cmd := exec.CommandContext(ctx, "subjs")
	cmd.Stdin = strings.NewReader(string(entries))
	out, err := cmd.Output()
	if err != nil {
		return
	}
	for _, linha := range strings.Split(string(out), "\n") {
		adicionarCandidato(dest, strings.TrimSpace(linha), "crawl")
	}
}

func coletarGetJS(ctx context.Context, urlsTxt string, dest map[string]string) {
	cmd := exec.CommandContext(ctx, "getJS", "--input", urlsTxt, "--complete")
	out, err := cmd.Output()
	if err != nil {
		return
	}
	for _, linha := range strings.Split(string(out), "\n") {
		adicionarCandidato(dest, strings.TrimSpace(linha), "historical")
	}
}

func coletarDeArquivo(caminho, fonte string, dest map[string]string) {
	arquivo, err := os.Open(caminho)
	if err != nil {
		return
	}
	defer arquivo.Close()

	scanner := bufio.NewScanner(arquivo)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)
	for scanner.Scan() {
		linha := strings.TrimSpace(scanner.Text())
		if lineaPareceJS(linha) {
			adicionarCandidato(dest, linha, fonte)
		}
	}
	// CORREÇÃO: erro do scanner (ex: linha maior que o buffer) agora é
	// reportado em vez de ser silenciosamente ignorado.
	if err := scanner.Err(); err != nil {
		fmt.Printf("[-] Erro lendo %s: %v\n", caminho, err)
	}
}

func lineaPareceJS(linha string) bool {
	u, err := url.Parse(linha)
	if err != nil {
		return false
	}
	return strings.HasSuffix(strings.ToLower(u.Path), ".js")
}

func adicionarCandidato(dest map[string]string, raw, fonte string) {
	normalizada, ok := normalizarURLJS(raw)
	if !ok {
		return
	}
	if ehInfraestruturaJS(normalizada) {
		return
	}
	// Prefere "crawl" sobre "historical" quando a URL aparece nas duas.
	if anterior, existe := dest[normalizada]; !existe || (fonte == "crawl" && anterior != "crawl") {
		dest[normalizada] = fonte
	}
}

func escreverCandidates(jsDir string, candidatos map[string]string) {
	urls := make([]string, 0, len(candidatos))
	for u := range candidatos {
		urls = append(urls, u)
	}
	sort.Strings(urls)

	candPath := filepath.Join(jsDir, "candidates.tsv")
	f, err := os.Create(candPath)
	if err != nil {
		fmt.Printf("[-] Erro criando candidates.tsv: %v\n", err)
		return
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, u := range urls {
		fmt.Fprintf(w, "%s\t%s\n", u, candidatos[u])
	}
	w.Flush()
}

// ---------------------------------------------------------------------------
// Normalização e classificação
// ---------------------------------------------------------------------------

func normalizarURLJS(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	if parsed.Host == "" {
		return "", false
	}
	if !strings.HasSuffix(strings.ToLower(parsed.Path), ".js") {
		return "", false
	}
	if strings.HasSuffix(parsed.Path, "/") {
		return "", false
	}
	parsed.Fragment = ""
	parsed.Scheme = scheme
	parsed.Host = strings.ToLower(parsed.Host)
	return parsed.String(), true
}

func ehInfraestruturaJS(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	pathLower := strings.ToLower(parsed.Path)

	prefixos := []string{
		"/cdn-cgi/", "/challenge-platform/", "/captcha/", "/recaptcha/",
		"/hcaptcha/", "/turnstile/",
	}
	for _, prefixo := range prefixos {
		if strings.Contains(pathLower, prefixo) {
			return true
		}
	}
	indicadores := []string{"challenge", "captcha", "turnstile", "recaptcha", "hcaptcha"}
	for _, ind := range indicadores {
		if strings.Contains(pathLower, ind) {
			return true
		}
	}
	return false
}

// caminhoECaminho extrai host e path de uma URL, para a classificação de tier.
func caminhoECaminho(raw string) (host, caminho string) {
	u, err := url.Parse(raw)
	if err != nil {
		return host, caminho
	}
	host = strings.ToLower(u.Hostname())
	caminho = strings.ToLower(u.Path)
	return
}

// classificarTier retorna HIGH/MEDIUM/LOW/SKIP para um candidato JS.
func classificarTier(host, caminho, fonte string) string {
	if ehTerceiro(host) {
		return "SKIP"
	}

	score := 0
	lower := caminho

	// Palavras-chave de alto valor no caminho.
	for _, kw := range []string{
		"app", "main", "config", "api", "auth", "endpoint", "route", "admin",
		"account", "dashboard", "bundle", "chunk", "webpack", "vite",
		"manifest", "login", "graphql",
	} {
		if strings.Contains(lower, kw) {
			score += 2
			break
		}
	}

	// Nome de arquivo curto (tende a ser bundle próprio, não vendor minificado).
	base := path.Base(strings.TrimSuffix(lower, "/"))
	if base != "" && len(base) < 28 {
		score++
	}

	// Descoberta no crawl atual tem prioridade sobre histórico.
	if fonte == "crawl" {
		score++
	}

	switch {
	case score >= 3:
		return "HIGH"
	case score == 2:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// ehTerceiro verifica se o host pertence a serviço de terceiros conhecido.
func ehTerceiro(host string) bool {
	host = strings.ToLower(host)
	for _, p := range palavrasTerceiros {
		if strings.Contains(host, p) {
			return true
		}
	}
	return false
}