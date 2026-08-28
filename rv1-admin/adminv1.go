package rv1admin

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// caminhosAdmin é a lista de paths comuns de painel administrativo
// testados em cada host resolvido.
var caminhosAdmin = []string{
	"/admin", "/admin/", "/administrator", "/admin/login", "/admin.php",
	"/wp-admin", "/wp-login.php", "/cpanel", "/manage", "/management",
	"/console", "/dashboard", "/admin-console", "/backend", "/panel",
	"/control", "/adminpanel", "/admin_area", "/admincp", "/webadmin",
	"/sysadmin", "/useradmin", "/admin/index.php", "/admin/dashboard",
	"/admin/home", "/login/admin", "/moderator", "/adm",
}

const (
	concorrencia  = 15
	timeoutPorReq = 8 * time.Second
)

// resultadoSonda é o retorno de uma requisição, usado tanto pro baseline
// quanto pra cada path testado.
type resultadoSonda struct {
	status int
	hash   string
	tam    int
}

// sondar faz um GET e devolve status HTTP + hash SHA256 do corpo + tamanho.
// O hash é o que permite comparar "essa resposta é igual à página de erro
// padrão do site, ou é conteúdo diferente" sem guardar o corpo inteiro.
func sondar(ctx context.Context, client *http.Client, url string) (*resultadoSonda, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeoutPorReq)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	corpo, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	soma := sha256.Sum256(corpo)
	return &resultadoSonda{status: resp.StatusCode, hash: hex.EncodeToString(soma[:]), tam: len(corpo)}, nil
}

// checarHost pega o baseline (uma URL que quase certamente não existe) e
// depois testa cada caminho de admin. Só reporta um "achado" quando a
// resposta é claramente diferente do baseline — isso é o que evita marcar
// toda URL com "admin" no path como um hit, em sites que devolvem HTTP 200
// com uma página de erro customizada pra qualquer rota inexistente (o
// problema mais comum de falso positivo nesse tipo de scan).
func checarHost(ctx context.Context, client *http.Client, host string, resultados *[]string, mu *sync.Mutex) {
	base := "https://" + host
	baselinePath := fmt.Sprintf("/gorecon-baseline-check-%d", rand.Intn(1_000_000))
	baseline, err := sondar(ctx, client, base+baselinePath)
	if err != nil {
		// Tenta HTTP puro se HTTPS falhar (sem certificado válido, etc.)
		base = "http://" + host
		baseline, err = sondar(ctx, client, base+baselinePath)
		if err != nil {
			return
		}
	}

	for _, caminho := range caminhosAdmin {
		select {
		case <-ctx.Done():
			return
		default:
		}

		r, err := sondar(ctx, client, base+caminho)
		if err != nil {
			continue
		}

		achou := false
		switch {
		case r.status == 200 && r.hash != baseline.hash:
			// Só conta como achado se o conteúdo for DIFERENTE do baseline
			// 404 do site — senão é só a mesma página de erro genérica.
			achou = true
		case r.status == 401 || r.status == 403:
			// O 401/403 "puro" é a fonte clássica de falso positivo em
			// massa: muitos WAF/CDN devolvem 403 com a MESMA página de
			// bloqueio pra qualquer path (aqui isso inflava admin-panel
			// com 3k+ entradas de "block"). Então, além do status, exigimos
			// que o CORPO seja diferente da página de bloqueio do baseline;
			// se for idêntica, é falso positivo e não reporta.
			if r.hash != baseline.hash {
				achou = true
			}
		case (r.status == 301 || r.status == 302) && r.status != baseline.status:
			achou = true
		}

		if achou {
			mu.Lock()
			*resultados = append(*resultados, base+caminho)
			mu.Unlock()
			fmt.Printf("[+] Possível admin panel: %s (HTTP %d)\n", base+caminho, r.status)
		}
	}
}

// EncontrarAdminPanels varre cada host em resolvidos.txt testando os
// caminhos comuns de admin panel, usando fingerprint por baseline 404 pra
// reduzir falso positivo. O resultado é gravado como mais um arquivo de
// vetor (vetores_ataque/admin-panel.txt), reaproveitando toda a
// infraestrutura de ingestão/dashboard que já existe pros outros vetores.
func EncontrarAdminPanels(ctx context.Context, empresa string) {
	fmt.Println("\n[+] Iniciando busca por Admin Panels (fingerprint via baseline 404)...")

	resultadosDir := filepath.Join(empresa, "resultados")
	resolvidosTxt := filepath.Join(resultadosDir, "resolvidos.txt")

	arquivo, err := os.Open(resolvidosTxt)
	if err != nil {
		fmt.Printf("[-] Não consegui abrir %s: %v\n", resolvidosTxt, err)
		return
	}
	var hosts []string
	scanner := bufio.NewScanner(arquivo)
	for scanner.Scan() {
		h := strings.TrimSpace(scanner.Text())
		if h != "" {
			hosts = append(hosts, h)
		}
	}
	arquivo.Close()

	if len(hosts) == 0 {
		fmt.Println("[-] Nenhum host resolvido encontrado. Abortando.")
		return
	}
	fmt.Printf("[*] Testando %d host(s) x %d caminho(s) de admin...\n", len(hosts), len(caminhosAdmin))

	client := &http.Client{
		Timeout: timeoutPorReq,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // não segue redirect, queremos o status bruto
		},
	}

	var (
		mu         sync.Mutex
		resultados []string
	)
	sem := make(chan struct{}, concorrencia)
	var wg sync.WaitGroup

	for _, host := range hosts {
		select {
		case <-ctx.Done():
			break
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			checarHost(ctx, client, h, &resultados, &mu)
		}(host)
	}
	wg.Wait()

	sort.Strings(resultados)

	pastaVetores := filepath.Join(resultadosDir, "vetores_ataque")
	if err := os.MkdirAll(pastaVetores, 0755); err != nil {
		fmt.Printf("[-] Erro criando pasta de vetores: %v\n", err)
		return
	}
	saida := filepath.Join(pastaVetores, "admin-panel.txt")
	if err := os.WriteFile(saida, []byte(strings.Join(resultados, "\n")+"\n"), 0644); err != nil {
		fmt.Printf("[-] Erro ao salvar %s: %v\n", saida, err)
		return
	}

	fmt.Printf("[+] Admin Panel finder concluído: %d achado(s) salvos em %s\n", len(resultados), saida)
}
