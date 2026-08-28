package rv1validacao

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Pipeline de vetores de ataque (revisado).
//
// Fluxo novo:
//
//   urls.txt (crawling bruto)
//     -> normalização canônica + dedup
//     -> filtro de escopo + remoção de extensões/ruído
//     -> priorização HIGH/MEDIUM/LOW por parâmetro/path
//     -> dedup por host+path (representante por grupo)
//     -> validação de vivo (httpx, ou probe nativo com rate limit)
//     -> ferramentas de confirmação opcionais (nuclei/kxss/dalfox/sqlmap)
//     -> persistência com status CANDIDATO/SUSPEITO/CONFIRMADO em
//        vetores_ataque/vetores.jsonl
//
// A lista crua NÃO vai para o banco. Apenas o que passa na triagem e é
// classificado em algum vetor é persistido para o dashboard.
// ---------------------------------------------------------------------------

const (
	concProbe        = 20              // requisições HTTP paralelas no probe nativo
	timeoutProbe     = 8 * time.Second // timeout por requisição de probe
	tamanhoLoteBanco = 500
)

// VetorAchado é a unidade persistida no banco e exibida no dashboard.
type VetorAchado struct {
	Tipo      string `json:"tipo"`
	URL       string `json:"url"`
	Status    string `json:"status"`              // CANDIDATO | SUSPEITO | CONFIRMADO
	Evidencia string `json:"evidencia,omitempty"` // ex.: "nuclei [high] CVE-..."
}

// ---------------------------------------------------------------------------
// Filtros/classificação
// ---------------------------------------------------------------------------

var paramsTracking = map[string]bool{
	"utm_source": true, "utm_medium": true, "utm_campaign": true, "utm_term": true,
	"utm_content": true, "utm_id": true, "fbclid": true, "gclid": true,
	"ref": true, "source": true, "campaign": true, "_ga": true, "mc_cid": true,
	"mc_eid": true, "ver": true, "_hsenc": true, "_hsmi": true, "igshid": true,
	"yclid": true, "msclkid": true, "twclid": true,
}

var extensoesRuido = []string{
	".js", ".css", ".png", ".svg", ".woff", ".woff2", ".jpg", ".jpeg", ".gif",
	".ico", ".ttf", ".eot", ".pdf", ".mp4", ".zip", ".webp", ".map",
}

var prefixosEstaticos = []string{
	"/wp-content/", "/static/", "/assets/", "/images/", "/themes/", "/plugins/",
	"/img/", "/css/", "/js/",
}

// mapaParamVetor associa nomes de parâmetro a vetores de vulnerabilidade.
var mapaParamVetor = map[string][]string{
	"q": {"xss", "sqli"}, "search": {"xss", "sqli"}, "query": {"xss", "sqli"},
	"s": {"xss"}, "keyword": {"xss"}, "text": {"xss"}, "callback": {"xss", "ssrf"},
	"cb": {"xss"}, "redirect": {"redirect", "ssrf"}, "url": {"redirect", "ssrf"},
	"uri": {"ssrf"}, "target": {"redirect", "ssrf"}, "dest": {"redirect", "ssrf"},
	"next": {"redirect"}, "return": {"redirect"}, "returnurl": {"redirect"},
	"rurl": {"redirect"}, "continue": {"redirect"}, "webhook": {"ssrf"},
	"link": {"ssrf"}, "domain": {"ssrf"}, "host": {"ssrf"}, "src": {"ssrf"},
	"file": {"lfi"}, "path": {"lfi"}, "doc": {"lfi"}, "template": {"lfi", "ssti"},
	"filepath": {"lfi"}, "filename": {"lfi"}, "include": {"lfi"}, "dir": {"lfi"},
	"page": {"sqli", "lfi"}, "id": {"sqli", "idor"}, "uid": {"sqli", "idor"},
	"user_id": {"sqli", "idor"}, "userid": {"idor"}, "account": {"idor"},
	"profile": {"idor"}, "order_id": {"idor"}, "invoice": {"idor"},
	"document_id": {"idor"}, "cat": {"sqli"}, "sort": {"sqli"}, "order": {"sqli"},
	"product_id": {"sqli"}, "article_id": {"sqli"}, "item": {"sqli"},
	"count": {"sqli"}, "cmd": {"rce"}, "exec": {"rce"}, "command": {"rce"},
	"action": {"rce"}, "do": {"rce"}, "func": {"rce"}, "function": {"rce"},
	"tpl": {"ssti"}, "msg": {"ssti"}, "message": {"ssti"}, "email": {"ssti"},
}

var palavrasPathAltoValor = []string{
	"admin", "api", "config", "upload", "download", "debug", "callback",
	"webhook", "auth", "login", "graphql", "manage", "dashboard", "internal",
}

func hasTool(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func fileExiste(caminho string) bool {
	_, err := os.Stat(caminho)
	return err == nil
}

// normalizarURL aplica a normalização canônica e devolve a URL limpa.
// Retorna false quando a URL deve ser descartada (sem host, esquema inválido).
func normalizarURL(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	if u.Hostname() == "" {
		return "", false
	}

	// host: lowercase, remove porta default e "www."
	host := strings.ToLower(u.Hostname())
	host = strings.TrimSuffix(host, ":80")
	host = strings.TrimSuffix(host, ":443")
	host = strings.TrimPrefix(host, "www.")
	// mantém porta não-default, se houver
	if p := u.Port(); p != "" && p != "80" && p != "443" {
		host = host + ":" + p
	}

	// remove fragmento e parâmetros de tracking
	u.Fragment = ""
	q := u.Query()
	for nome := range q {
		if paramsTracking[strings.ToLower(nome)] {
			q.Del(nome)
		}
	}
	// ordena parâmetros restantes na query string (canônico)
	u.RawQuery = orderedQuery(q)

	u.Scheme = scheme
	u.Host = host
	return u.String(), true
}

// orderedQuery serializa os parâmetros com nomes ordenados alfabeticamente.
func orderedQuery(values url.Values) string {
	if len(values) == 0 {
		return ""
	}
	nomes := make([]string, 0, len(values))
	for k := range values {
		nomes = append(nomes, k)
	}
	sort.Strings(nomes)

	var pares []string
	for _, k := range nomes {
		vs := values[k]
		sort.Strings(vs)
		for _, v := range vs {
			pares = append(pares, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	return strings.Join(pares, "&")
}

func ehExtensaoRuido(hostPath string) bool {
	low := strings.ToLower(hostPath)
	for _, e := range extensoesRuido {
		if strings.HasSuffix(low, e) {
			return true
		}
	}
	for _, p := range prefixosEstaticos {
		if strings.Contains(low, p) {
			return true
		}
	}
	return false
}

func prioridade(u *url.URL) string {
	score := 0
	q := u.Query()
	for nome := range q {
		switch strings.ToLower(nome) {
		case "redirect", "url", "next", "return", "returnurl", "target", "dest",
			"file", "path", "doc", "template", "cmd", "exec", "command",
			"callback", "webhook":
			score += 3
		case "id", "user_id", "uid", "sort", "order", "q", "search", "query",
			"page", "cat", "action", "do":
			score += 2
		default:
			score++
		}
	}

	lowPath := strings.ToLower(u.Path)
	for _, kw := range palavrasPathAltoValor {
		if strings.Contains(lowPath, kw) {
			score += 2
			break
		}
	}
	for _, ext := range []string{".php", ".asp", ".aspx", ".jsp", ".do", ".json"} {
		if strings.HasSuffix(lowPath, ext) {
			score++
			break
		}
	}

	switch {
	case score >= 4:
		return "HIGH"
	case score >= 2:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// classificarVetores retorna a lista de vetores associados a uma URL, com
// base nos nomes dos query params. Vazio = nenhum vetor reconhecido.
func classificarVetores(u *url.URL) []string {
	visto := map[string]bool{}
	var tipos []string
	for nome := range u.Query() {
		nomeLow := strings.ToLower(nome)
		if t, ok := mapaParamVetor[nomeLow]; ok {
			for _, tipo := range t {
				if !visto[tipo] {
					visto[tipo] = true
					tipos = append(tipos, tipo)
				}
			}
		}
	}
	sort.Strings(tipos)
	return tipos
}

func carregarDominios(caminho string) []string {
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
		// aceita entrada como URL também (ex.: https://ibwc.gov)
		if strings.Contains(d, "://") {
			if u, err := url.Parse(d); err == nil {
				d = u.Hostname()
			}
		}
		d = strings.TrimPrefix(d, "www.")
		if d == "" || strings.HasPrefix(d, "#") {
			continue
		}
		dominios = append(dominios, d)
	}
	_ = sc.Err()
	return dominios
}

func hostEmEscopo(host string, dominios []string) bool {
	host = strings.ToLower(host)
	for _, d := range dominios {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Probe de vivo (nativo, com fallback; httpx é preferido quando presente)
// ---------------------------------------------------------------------------

func probeVivoNative(ctx context.Context, client *http.Client, alvo string) (status int, morto bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, alvo, nil)
	if err != nil {
		return 0, true
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; GoRecon/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		// fallback GET quando HEAD não é suportado/aceito
		req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, alvo, nil)
		req2.Header.Set("User-Agent", "Mozilla/5.0 (compatible; GoRecon/1.0)")
		resp2, err2 := client.Do(req2)
		if err2 != nil {
			return 0, true
		}
		defer resp2.Body.Close()
		io.Copy(io.Discard, io.LimitReader(resp2.Body, 2048))
		resp = resp2
	} else {
		defer resp.Body.Close()
	}

	code := resp.StatusCode
	switch code {
	case 200, 201, 204, 301, 302, 401, 403, 405:
		// redirect para raiz/login = endpoint morto/fora de contexto
		if code == 301 || code == 302 {
			loc := resp.Header.Get("Location")
			locPath := ""
			if u, err := url.Parse(loc); err == nil {
				locPath = u.Path
			}
			if locPath == "" || locPath == "/" || strings.Contains(locPath, "/login") || strings.Contains(locPath, "/wp-login") {
				return code, true
			}
		}
		return code, false
	default:
		return code, true
	}
}

// ---------------------------------------------------------------------------
// Ferramentas de confirmação (opcionais, detectadas via PATH)
// ---------------------------------------------------------------------------

// rodarNuclei roda o nuclei com controle de ruído (rate-limit/concorrência
// baixos, apenas templates passivos) sobre a lista de alvos vivos.
func rodarNuclei(ctx context.Context, alvos []string, achados *[]VetorAchado, mu *sync.Mutex) {
	if !hasTool("nuclei") {
		fmt.Println("[!] nuclei não encontrado — confirmação de RCE/LFI/SSTI pulada.")
		return
	}

	tmp, err := os.CreateTemp("", "nuclei-*.txt")
	if err != nil {
		return
	}
	tmp.WriteString(strings.Join(alvos, "\n"))
	tmpName := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpName)

	cmd := exec.CommandContext(ctx, "nuclei",
		"-l", tmpName,
		"-tags", "rce,lfi,ssti,exposure,misconfig",
		"-rate-limit", "40",
		"-c", "20",
		"-timeout", "8",
		"-silent",
		"-jsonl",
		"-duc",
	)
	out, err := cmd.Output()
	if err != nil {
		// nuclei retorna exit != 0 quando há erro/sem match; ignoramos
		if len(out) == 0 {
			fmt.Println("[!] nuclei não retornou saída.")
			return
		}
	}

	for _, linha := range strings.Split(string(out), "\n") {
		linha = strings.TrimSpace(linha)
		if linha == "" {
			continue
		}
		var r struct {
			Matched string `json:"matched-at"`
			Info    struct {
				Name     string   `json:"name"`
				Severity string   `json:"severity"`
				Tags     []string `json:"tags"`
			} `json:"info"`
		}
		if json.Unmarshal([]byte(linha), &r) != nil || r.Matched == "" {
			continue
		}
		tipo := extrairTipoNuclei(r.Info.Tags, r.Info.Name)
		status := "SUSPEITO"
		if r.Info.Severity == "high" || r.Info.Severity == "critical" {
			status = "CONFIRMADO"
		}
		mu.Lock()
		*achados = append(*achados, VetorAchado{
			Tipo:      tipo,
			URL:       r.Matched,
			Status:    status,
			Evidencia: "nuclei [" + r.Info.Severity + "] " + r.Info.Name,
		})
		mu.Unlock()
	}
}

func extrairTipoNuclei(tags []string, nome string) string {
	baixo := strings.ToLower(nome + " " + strings.Join(tags, " "))
	switch {
	case strings.Contains(baixo, "ssti") || strings.Contains(baixo, "template-injection"):
		return "ssti"
	case strings.Contains(baixo, "lfi") || strings.Contains(baixo, "local-file"):
		return "lfi"
	case strings.Contains(baixo, "rce") || strings.Contains(baixo, "remote-code"):
		return "rce"
	case strings.Contains(baixo, "ssrf"):
		return "ssrf"
	case strings.Contains(baixo, "sqli") || strings.Contains(baixo, "sql-injection"):
		return "sqli"
	case strings.Contains(baixo, "xss") || strings.Contains(baixo, "cross-site"):
		return "xss"
	default:
		return "exposure"
	}
}

// xssStrikeCmdBase localiza o XSStrike e devolve o prefixo de comando.
// O XSStrike é uma ferramenta Python; na VPS fica em:
//   /home/ubuntu/Download/XSStrike/xsstrike.py
// Executado como: python3 <caminho>/xsstrike.py ...
// Suporta override via env XSSTRIKE_PATH.
func xssStrikeCmdBase() ([]string, bool) {
	if p := strings.TrimSpace(os.Getenv("XSSTRIKE_PATH")); p != "" && fileExiste(p) {
		return []string{"python3", p}, true
	}
	if fileExiste("/home/ubuntu/Download/XSStrike/xsstrike.py") {
		return []string{"python3", "/home/ubuntu/Download/XSStrike/xsstrike.py"}, true
	}
	return nil, false
}

// rodarXSSStrike confirma XSS refletido nos endpoints de tipo "xss".
// Mais avançado que o kxss (monta payloads, testa reflexão e contexto).
// Como é um alvo por processo, roda apenas nos candidatos já vivos e com
// parâmetro de tipo xss para não gerar ruído/volume.
func rodarXSSStrike(ctx context.Context, alvos []string, achados *[]VetorAchado, mu *sync.Mutex) {
	base, ok := xssStrikeCmdBase()
	if !ok {
		fmt.Println("[!] XSStrike não encontrado — confirmação XSS pulada.")
		return
	}
	for _, alvo := range alvos {
		select {
		case <-ctx.Done():
			return
		default:
		}
		args := append(append([]string{}, base...), "-u", alvo, "--skip", "--skip-dom")
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		out, err := cmd.Output()
		if err != nil && len(out) == 0 {
			continue
		}
		texto := strings.ToLower(string(out))
		if strings.Contains(texto, "reflected") || strings.Contains(texto, "injection point") || strings.Contains(texto, "payload:") {
			mu.Lock()
			*achados = append(*achados, VetorAchado{
				Tipo:      "xss",
				URL:       alvo,
				Status:    "SUSPEITO",
				Evidencia: "XSStrike — possível XSS refletido",
			})
			mu.Unlock()
		}
	}
}

// sqlmapCmdBase localiza o sqlmap e devolve o prefixo de comando.
// Na VPS o sqlmap é executado como:
//   python3 /home/ubuntu/Download/sqlmap-dev/sqlmap.py ...
// Suporta override via env SQLMAP_PATH.
func sqlmapCmdBase() ([]string, bool) {
	if p := strings.TrimSpace(os.Getenv("SQLMAP_PATH")); p != "" && fileExiste(p) {
		return []string{"python3", p}, true
	}
	if fileExiste("/home/ubuntu/Download/sqlmap-dev/sqlmap.py") {
		return []string{"python3", "/home/ubuntu/Download/sqlmap-dev/sqlmap.py"}, true
	}
	return nil, false
}

func rodarSqlmap(ctx context.Context, alvos []string, achados *[]VetorAchado, mu *sync.Mutex) {
	base, ok := sqlmapCmdBase()
	if !ok {
		fmt.Println("[!] sqlmap não encontrado — confirmação SQLi pulada.")
		return
	}
	// apenas endpoints de maior valor; nunca em massa
	for _, alvo := range alvos {
		select {
		case <-ctx.Done():
			return
		default:
		}
		args := append(append([]string{}, base...),
			"-u", alvo,
			"--batch",
			"--level=1",
			"--risk=1",
			"--flush-session",
			"--disable-coloring",
		)
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		out, _ := cmd.Output()
		if strings.Contains(string(out), "is vulnerable") || strings.Contains(string(out), "sqlmap identified") {
			mu.Lock()
			*achados = append(*achados, VetorAchado{
				Tipo:      "sqli",
				URL:       alvo,
				Status:    "CONFIRMADO",
				Evidencia: "sqlmap — injeção SQL identificada",
			})
			mu.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// ProcessarVetores — entrada do pipeline
// ---------------------------------------------------------------------------

func ProcessarVetores(ctx context.Context, arquivoAlvos, empresa string) {
	fmt.Println("\n[+] Iniciando pipeline de vetores de ataque (triagem + confirmação)...")

	resultadosDir := filepath.Join(empresa, "resultados")
	vetoresDir := filepath.Join(resultadosDir, "vetores_ataque")
	if err := os.MkdirAll(vetoresDir, 0755); err != nil {
		fmt.Printf("[-] Erro criando pasta de vetores: %v\n", err)
		return
	}

	dominios := carregarDominios(arquivoAlvos)
	if len(dominios) == 0 {
		fmt.Println("[!] Não foi possível carregar a lista de alvos — filtro de escopo desativado (tudo em escopo).")
	}

	// 1. Normalização + dedup + escopo + ruído em MEMÓRIA.
	const (
		arquivoAuditoria = "candidatos_brutos.tsv"
		arquivoBaixa     = "baixa_prioridade.txt"
		arquivoVetores   = "vetores.jsonl"
	)

	candidatos := make(map[string]string) // url canônica -> prioridade

	// Fontes de URL. Historicamente urls.txt fica vazio quando Gau/Waymore
	// estão comentados no main.go — então lemos também as saídas brutas de
	// crawling e os endpoints JS já extraídos, garantindo input pra triagem
	// de vetores e pras ferramentas de confirmação.
	fontes := []string{
		filepath.Join(resultadosDir, "urls.txt"),
		filepath.Join(resultadosDir, "waymore.txt"),
		filepath.Join(resultadosDir, "gau.txt"),
		filepath.Join(resultadosDir, "xnlinkfinder.txt"),
		filepath.Join(resultadosDir, "api", "endpoints.txt"),
	}

	adicionar := func(raw string) {
		norm, ok := normalizarURL(raw)
		if !ok {
			return
		}
		u, err := url.Parse(norm)
		if err != nil {
			return
		}
		// escopo
		if len(dominios) > 0 && !hostEmEscopo(u.Hostname(), dominios) {
			return
		}
		// extensão/ruído
		if ehExtensaoRuido(u.Path) {
			return
		}
		// prioridade
		p := prioridade(u)
		if atual, existe := candidatos[norm]; !existe || p == "HIGH" || (p == "MEDIUM" && atual != "HIGH") {
			candidatos[norm] = p
		}
	}

	for _, fonte := range fontes {
		if f, err := os.Open(fonte); err == nil {
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 1024*1024), 10*1024*1024)
			for sc.Scan() {
				if linha := strings.TrimSpace(sc.Text()); linha != "" {
					adicionar(linha)
				}
			}
			if err := sc.Err(); err != nil {
				fmt.Printf("[!] erro ao ler %s: %v\n", fonte, err)
			}
			f.Close()
		}
	}
	if len(candidatos) == 0 {
		fmt.Println("[-] Nenhuma URL candidata após a triagem (fontes de crawling vazias).")
		return
	}

	// salva auditoria (todos os candidatos) e separa baixa prioridade
	var urlsHIGHMEDIUM []string
	var urlsLOW []string
	for u, p := range candidatos {
		if p == "LOW" {
			urlsLOW = append(urlsLOW, u)
		} else {
			urlsHIGHMEDIUM = append(urlsHIGHMEDIUM, u)
		}
	}
	sort.Strings(urlsHIGHMEDIUM)
	sort.Strings(urlsLOW)

	// auditoria bruta
	var linhasAud []string
	for u, p := range candidatos {
		linhasAud = append(linhasAud, u+"\t"+p)
	}
	sort.Strings(linhasAud)
	escreverLinhas(filepath.Join(vetoresDir, arquivoAuditoria), linhasAud)
	escreverLinhas(filepath.Join(vetoresDir, arquivoBaixa), urlsLOW)

	fmt.Printf("[*] Candidatos triados: %d (HIGH/MEDIUM), %d (LOW), %d descartados por escopo/ruído.\n",
		len(urlsHIGHMEDIUM), len(urlsLOW), 0)

	// 2. Dedup por host+path ANTES do probe de vivo.
	representantes := dedupPorHostPath(urlsHIGHMEDIUM)

	// 3. Validação de vivo.
	vivos := validarVivos(ctx, representantes)

	// 4. Monta os achados "CANDIDATO" a partir dos vivos, classificando por vetor.
	achados := buildAchadosCandidatos(vivos)

	var mu sync.Mutex
	// 4b. Confirmação opcional (apenas sobre URLs vivas e priorizadas).
	// XSStrike roda somente nos candidatos de tipo xss (um alvo por processo).
	rodarXSSStrike(ctx, filtrarPorTipo(vivos, "xss"), &achados, &mu)
	rodarNuclei(ctx, vivos, &achados, &mu)

	// sqlmap apenas para candidatos sqli HIGH/MEDIUM (baixo volume)
	urlsSQLi := filtrarPorTipo(vivos, "sqli")
	rodarSqlmap(ctx, urlsSQLi, &achados, &mu)

	// 5. Persistência: dedup por (tipo,url) e grava JSONL.
	final := dedupAchados(achados)
	escreverVetoresJSONL(filepath.Join(vetoresDir, arquivoVetores), final)

	fmt.Printf("[+] Pipeline de vetores concluído: %d achados persistidos (vetores.jsonl).\n", len(final))

	// Limpeza dos arquivos temporários brutos (mantém comportamento anterior)
	for _, lixo := range []string{"gau.txt", "jshunter.txt", "waymore.txt", "xnlinkfinder.txt"} {
		_ = os.Remove(filepath.Join(resultadosDir, lixo))
	}
}

// dedupPorHostPath mantém um representante por scheme://host:port/path,
// preferindo a URL de maior prioridade (order of input preserva HIGH/MEDIUM).
func dedupPorHostPath(urls []string) []string {
	grupos := make(map[string]string)
	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		chave := parsed.Scheme + "://" + parsed.Host + parsed.Path
		if _, ok := grupos[chave]; !ok {
			grupos[chave] = u
		}
	}
	out := make([]string, 0, len(grupos))
	for _, u := range grupos {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

func validarVivos(ctx context.Context, urls []string) []string {
	var (
		vivos []string
		mu    sync.Mutex
	)
	if hasTool("httpx") {
		fmt.Printf("[*] Validando %d endpoints (httpx, rate-limit)...\n", len(urls))
		tmp, _ := os.CreateTemp("", "httpx-*.txt")
		tmp.WriteString(strings.Join(urls, "\n"))
		tmpName := tmp.Name()
		tmp.Close()
		defer os.Remove(tmpName)

		outPath := tmpName + ".out"
		cmd := exec.CommandContext(ctx, "httpx",
			"-l", tmpName,
			"-silent",
			"-threads", "25",
			"-rate-limit", "50",
			"-timeout", "8",
			"-sc", "-location",
			"-mc", "200,201,204,301,302,401,403,405",
			"-o", outPath,
		)
		_ = cmd.Run()

		if f, err := os.Open(outPath); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				linha := strings.TrimSpace(sc.Text())
				if linha == "" {
					continue
				}
				// extrai a URL da linha (formato: https://... [200])
				if idx := strings.Index(linha, " ["); idx > 0 {
					vivos = append(vivos, strings.TrimSpace(linha[:idx]))
				} else {
					vivos = append(vivos, linha)
				}
			}
			if err := sc.Err(); err != nil {
				fmt.Printf("[!] erro ao ler saída do httpx: %v\n", err)
			}
			f.Close()
			_ = os.Remove(outPath)
		}
		return uniq(vivos)
	}

	// fallback nativo
	fmt.Printf("[*] Validando %d endpoints (probe nativo HEAD/GET)...\n", len(urls))
	client := &http.Client{Timeout: timeoutProbe}
	sem := make(chan struct{}, concProbe)
	var wg sync.WaitGroup
	for _, u := range urls {
		select {
		case <-ctx.Done():
			wg.Wait()
			return uniq(vivos)
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			_, morto := probeVivoNative(ctx, client, u)
			if !morto {
				mu.Lock()
				vivos = append(vivos, u)
				mu.Unlock()
			}
		}(u)
	}
	wg.Wait()
	return uniq(vivos)
}

// buildAchadosCandidatos gera achados de status CANDIDATO a partir das URLs
// vivas, classificando cada uma nos vetores correspondentes aos parâmetros.
func buildAchadosCandidatos(vivos []string) []VetorAchado {
	var out []VetorAchado
	for _, u := range vivos {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		tipos := classificarVetores(parsed)
		for _, t := range tipos {
			out = append(out, VetorAchado{Tipo: t, URL: u, Status: "CANDIDATO"})
		}
	}
	return out
}

// filtrarPorTipo retorna as URLs vivas que têm o parâmetro do tipo desejado.
func filtrarPorTipo(vivos []string, tipo string) []string {
	var out []string
	for _, u := range vivos {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		for _, t := range classificarVetores(parsed) {
			if t == tipo {
				out = append(out, u)
				break
			}
		}
	}
	return out
}

func dedupAchados(achados []VetorAchado) []VetorAchado {
	// mantém o achado de maior status por (tipo,url)
	rank := map[string]int{"CANDIDATO": 1, "SUSPEITO": 2, "CONFIRMADO": 3}
	melhor := make(map[string]VetorAchado)
	ordem := []string{}
	for _, a := range achados {
		chave := a.Tipo + "|" + a.URL
		if atual, ok := melhor[chave]; !ok {
			melhor[chave] = a
			ordem = append(ordem, chave)
		} else if rank[a.Status] > rank[atual.Status] {
			melhor[chave] = a
		}
	}
	out := make([]VetorAchado, 0, len(ordem))
	for _, chave := range ordem {
		out = append(out, melhor[chave])
	}
	sort.Slice(out, func(i, j int) bool {
		// CONFIRMADO primeiro, depois SUSPEITO, depois CANDIDATO
		ri, rj := rank[out[i].Status], rank[out[j].Status]
		if ri != rj {
			return ri > rj
		}
		return out[i].URL < out[j].URL
	})
	return out
}

func escreverVetoresJSONL(caminho string, achados []VetorAchado) {
	f, err := os.Create(caminho)
	if err != nil {
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, a := range achados {
		b, _ := json.Marshal(a)
		w.Write(b)
		w.WriteByte('\n')
	}
	w.Flush()
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
		w.WriteByte('\n')
	}
	w.Flush()
}

func uniq(in []string) []string {
	visto := map[string]bool{}
	var out []string
	for _, s := range in {
		if !visto[s] {
			visto[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
