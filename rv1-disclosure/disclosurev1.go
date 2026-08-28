package rv1disclosure

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// caminhosActuator são os endpoints do Spring Boot Actuator mais
// interessantes pra bug bounty — vários deles (heapdump, env, shutdown)
// vazam segredo direto ou permitem ação destrutiva.
var caminhosActuator = []string{
	"/actuator", "/actuator/health", "/actuator/info", "/actuator/env",
	"/actuator/beans", "/actuator/configprops", "/actuator/mappings",
	"/actuator/heapdump", "/actuator/threaddump", "/actuator/loggers",
	"/actuator/metrics", "/actuator/httptrace", "/actuator/shutdown",
	"/actuator/auditevents", "/actuator/scheduledtasks", "/actuator/sessions",
	"/actuator/trace", "/actuator/dump",
}

// caminhosGraphQL são os paths mais comuns de endpoint GraphQL.
var caminhosGraphQL = []string{"/graphql", "/graphql/", "/api/graphql", "/v1/graphql", "/gql", "/query"}

const (
	concorrencia  = 15
	timeoutPorReq = 8 * time.Second
)

func lerHosts(caminho string) []string {
	arquivo, err := os.Open(caminho)
	if err != nil {
		return nil
	}
	defer arquivo.Close()
	var hosts []string
	scanner := bufio.NewScanner(arquivo)
	for scanner.Scan() {
		h := strings.TrimSpace(scanner.Text())
		if h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// checarActuator testa cada caminho de Actuator num host. Considera achado
// qualquer 200 com corpo não-vazio (o Actuator normalmente responde JSON;
// mesmo /actuator/health "cru" já confirma que o endpoint está exposto).
func checarActuator(ctx context.Context, client *http.Client, host string, resultados *[]string, mu *sync.Mutex) {
	for _, base := range []string{"https://" + host, "http://" + host} {
		encontrouBase := false
		for _, caminho := range caminhosActuator {
			select {
			case <-ctx.Done():
				return
			default:
			}
			url := base + caminho
			reqCtx, cancel := context.WithTimeout(ctx, timeoutPorReq)
			req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
			if err != nil {
				cancel()
				continue
			}
			resp, err := client.Do(req)
			cancel()
			if err != nil {
				continue
			}
			corpo, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()

			// Só conta como exposto se o corpo PARECER resposta de Actuator:
			// JSON com "_links" (HAL), "propertySources" (/env), "configprops",
			// "archaius" (Spring Cloud) ou status field do health. Um 200 com
			// HTML genérico (ex.: página de erro customizada do IIS/ASP.NET)
			// era contado como actuator exposto e gerava dezenas de falsos
			// positivos em massa.
			if resp.StatusCode == 200 && pareceRespostaActuator(corpo) {
				mu.Lock()
				*resultados = append(*resultados, url)
				mu.Unlock()
				fmt.Printf("[+] Actuator exposto: %s\n", url)
				encontrouBase = true
			}
		}
		// Se já achou algo em HTTPS, não precisa repetir em HTTP puro.
		if encontrouBase {
			break
		}
	}
}

// pareceRespostaActuator decide se o corpo de uma resposta 200 realmente
// se parece com um endpoint do Spring Boot Actuator. Isso filtra falsos
// positivos clássicos: páginas de erro customizada (IIS/ASP.NET), HTML de
// "not found", portais com cache, etc., que respondem 200 pra qualquer path.
func pareceRespostaActuator(corpo []byte) bool {
	texto := strings.ToLower(string(corpo))
	// JSON de Actuator/HAL/Spring costuma ter um destes marcadores:
	marcadores := []string{
		`"_links"`, `"propertySources"`, `"configprops"`, `"archaius"`,
		`"measurements"`, `"base-unit"`, `"service.disk"`, `"spring"`,
	}
	for _, m := range marcadores {
		if strings.Contains(texto, m) {
			return true
		}
	}
	// "/actuator/health" puro: {"status":"UP"} ou {"status":"DOWN"}
	if strings.Contains(texto, `"status":"up"`) || strings.Contains(texto, `"status":"down"`) {
		return true
	}
	// "/actuator" raiz normalmente é JSON de listagem de links.
	if strings.HasPrefix(texto, "{") && strings.Contains(texto, "actuator") {
		return true
	}
	return false
}

// checarGraphQL manda uma query de introspecção mínima em cada path comum
// de GraphQL. Se a resposta contiver "__schema" ou "queryType", a
// introspecção está habilitada — o que normalmente permite mapear o schema
// inteiro da API (nomes de campos, mutations sensíveis, etc.).
func checarGraphQL(ctx context.Context, client *http.Client, host string, resultados *[]string, mu *sync.Mutex) {
	introspeccao := []byte(`{"query":"{__schema{queryType{name}}}"}`)

	for _, base := range []string{"https://" + host, "http://" + host} {
		for _, caminho := range caminhosGraphQL {
			select {
			case <-ctx.Done():
				return
			default:
			}
			url := base + caminho
			reqCtx, cancel := context.WithTimeout(ctx, timeoutPorReq)
			req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(introspeccao))
			if err != nil {
				cancel()
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			cancel()
			if err != nil {
				continue
			}
			corpo, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			corpoStr := string(corpo)

			if resp.StatusCode == 200 && (strings.Contains(corpoStr, "__schema") || strings.Contains(corpoStr, "queryType")) {
				mu.Lock()
				*resultados = append(*resultados, url)
				mu.Unlock()
				fmt.Printf("[+] GraphQL com introspecção ativa: %s\n", url)
			}
		}
	}
}

// EscanearDisclosure varre todos os hosts resolvidos em busca de endpoints
// Spring Boot Actuator expostos e GraphQL com introspecção habilitada.
// Os achados viram mais dois arquivos de vetor (actuator.txt, graphql.txt)
// dentro de vetores_ataque/, então aparecem automaticamente no dashboard
// junto dos outros vetores — inclusive nos filtros por tipo, sem precisar
// de nenhuma mudança no backend do dashboard.
func EscanearDisclosure(ctx context.Context, empresa string) {
	fmt.Println("\n[+] Iniciando scanner de Actuator + GraphQL...")

	resultadosDir := filepath.Join(empresa, "resultados")
	hosts := lerHosts(filepath.Join(resultadosDir, "resolvidos.txt"))
	if len(hosts) == 0 {
		fmt.Println("[-] Nenhum host resolvido encontrado. Abortando.")
		return
	}
	fmt.Printf("[*] Testando %d host(s) para Actuator (%d paths) e GraphQL (%d paths)...\n",
		len(hosts), len(caminhosActuator), len(caminhosGraphQL))

	client := &http.Client{Timeout: timeoutPorReq}

	var (
		muActuator, muGraphQL           sync.Mutex
		achadosActuator, achadosGraphQL []string
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
			checarActuator(ctx, client, h, &achadosActuator, &muActuator)
			checarGraphQL(ctx, client, h, &achadosGraphQL, &muGraphQL)
		}(host)
	}
	wg.Wait()

	sort.Strings(achadosActuator)
	sort.Strings(achadosGraphQL)

	pastaVetores := filepath.Join(resultadosDir, "vetores_ataque")
	if err := os.MkdirAll(pastaVetores, 0755); err != nil {
		fmt.Printf("[-] Erro criando pasta de vetores: %v\n", err)
		return
	}

	salvar := func(nome string, linhas []string) {
		caminho := filepath.Join(pastaVetores, nome)
		if err := os.WriteFile(caminho, []byte(strings.Join(linhas, "\n")+"\n"), 0644); err != nil {
			fmt.Printf("[-] Erro ao salvar %s: %v\n", caminho, err)
		}
	}
	salvar("actuator.txt", achadosActuator)
	salvar("graphql.txt", achadosGraphQL)

	fmt.Printf("[+] Disclosure scanner concluído: %d Actuator, %d GraphQL expostos.\n",
		len(achadosActuator), len(achadosGraphQL))
}
