package rv1cdn

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Resultado é um host resolvido classificado como atrás de CDN ou não.
// Salvo em cdn-recon.json e depois lido por database_create.PopularBanco
// (inserirCdn). Pensado como base pro futuro port scanner: dá pra pular
// IPs de CDN (que não são a infra real do alvo) e focar só nos "origin".
type Resultado struct {
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Provedor string `json:"provedor"` // "" quando EhCDN=false
	EhCDN    bool   `json:"eh_cdn"`
}

// faixa é um bloco CIDR conhecido de um provedor de CDN.
type faixa struct {
	provedor string
	rede     *net.IPNet
}

// rangesCDN é uma lista NÃO EXAUSTIVA de blocos IP publicamente
// documentados dos principais provedores de CDN/WAF. Provedores como
// Cloudflare e AWS publicam listas oficiais atualizadas em JSON
// (https://www.cloudflare.com/ips-v4, https://ip-ranges.amazonaws.com) —
// buscar essas listas dinamicamente é uma melhoria natural pra depois;
// por ora isso cobre a maioria dos casos comuns combinado com a
// heurística de CNAME abaixo.
var rangesCDN = construirRanges(map[string][]string{
	"Cloudflare": {
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
		"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
		"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
		"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	},
	"Fastly": {
		"23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23",
		"103.245.224.0/24", "104.156.80.0/20", "151.101.0.0/16", "157.52.64.0/18",
		"172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16",
	},
	"Akamai": {
		"23.32.0.0/11", "23.192.0.0/11", "2.16.0.0/13", "95.100.0.0/15", "96.6.0.0/15",
	},
	"AWS CloudFront": {
		"13.32.0.0/15", "13.35.0.0/16", "13.224.0.0/14", "52.84.0.0/15",
		"54.182.0.0/16", "54.192.0.0/16", "54.230.0.0/16", "99.84.0.0/16",
		"143.204.0.0/16", "204.246.164.0/22",
	},
	"Google Cloud CDN": {
		"34.96.0.0/20", "34.104.0.0/21",
	},
	"Azure Front Door / CDN": {
		"13.107.6.0/24", "13.107.9.0/24", "13.107.42.0/24", "13.107.43.0/24", "150.171.16.0/22",
	},
	"Imperva / Incapsula": {
		"45.64.64.0/22", "103.28.248.0/22", "107.154.0.0/16", "149.126.72.0/21",
		"185.11.124.0/22", "192.230.64.0/18", "199.83.128.0/21",
	},
})

func construirRanges(m map[string][]string) []faixa {
	var lista []faixa
	for provedor, blocos := range m {
		for _, bloco := range blocos {
			_, rede, err := net.ParseCIDR(bloco)
			if err != nil {
				continue
			}
			lista = append(lista, faixa{provedor: provedor, rede: rede})
		}
	}
	return lista
}

// cnameIndicaCDN é a heurística complementar: quando o range de IP não
// bate com nada conhecido, o próprio hostname do CNAME quase sempre
// entrega o provedor (ex: "*.cloudfront.net", "*.akamaiedge.net").
var cnameIndicaCDN = map[string]string{
	"cloudflare":        "Cloudflare",
	"cloudfront":        "AWS CloudFront",
	"akamai":            "Akamai",
	"akamaiedge":        "Akamai",
	"fastly":            "Fastly",
	"azureedge":         "Azure Front Door / CDN",
	"azurefd":           "Azure Front Door / CDN",
	"incapdns":          "Imperva / Incapsula",
	"edgekey":           "Akamai",
	"edgesuite":         "Akamai",
	"cdn77":             "CDN77",
	"stackpathdns":      "StackPath",
	"fastlylb":          "Fastly",
	"googleusercontent": "Google Cloud CDN",
}

// classificarIP checa um IP contra os ranges conhecidos.
func classificarIP(ip net.IP) (provedor string, ehCDN bool) {
	for _, f := range rangesCDN {
		if f.rede.Contains(ip) {
			return f.provedor, true
		}
	}
	return "", false
}

// classificarCNAME olha a cadeia de CNAME em busca de palavras-chave de
// CDN conhecidas, usado como fallback quando o IP não bate com os ranges.
func classificarCNAME(host string) (provedor string, ehCDN bool) {
	cname, err := net.LookupCNAME(host)
	if err != nil {
		return "", false
	}
	cnameLower := strings.ToLower(cname)
	for chave, nome := range cnameIndicaCDN {
		if strings.Contains(cnameLower, chave) {
			return nome, true
		}
	}
	return "", false
}

const concorrencia = 20

// FiltrarCDN resolve cada host de resolvidos.txt pro IP real, classifica
// se está atrás de CDN/WAF conhecido (por range de IP e, como fallback,
// por palavra-chave no CNAME) e salva o resultado em cdn-recon.json.
// Serve tanto pra visibilidade no dashboard quanto de base pro futuro port
// scanner (pular IP de CDN e focar nos hosts com IP de origem real).
func FiltrarCDN(ctx context.Context, empresa string) {
	fmt.Println("\n[+] Iniciando classificação de CDN por IP...")

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
	fmt.Printf("[*] Resolvendo e classificando %d host(s)...\n", len(hosts))

	var (
		mu        sync.Mutex
		resultado []Resultado
	)
	sem := make(chan struct{}, concorrencia)
	var wg sync.WaitGroup
	resolver := &net.Resolver{}

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

			lookupCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
			defer cancel()
			ips, err := resolver.LookupIPAddr(lookupCtx, h)
			if err != nil || len(ips) == 0 {
				return
			}
			ip := ips[0].IP

			provedor, ehCDN := classificarIP(ip)
			if !ehCDN {
				provedor, ehCDN = classificarCNAME(h)
			}

			mu.Lock()
			resultado = append(resultado, Resultado{Host: h, IP: ip.String(), Provedor: provedor, EhCDN: ehCDN})
			mu.Unlock()
		}(host)
	}
	wg.Wait()

	sort.Slice(resultado, func(i, j int) bool { return resultado[i].Host < resultado[j].Host })

	saida := filepath.Join(resultadosDir, "cdn-recon.json")
	dados, err := json.MarshalIndent(resultado, "", "  ")
	if err != nil {
		fmt.Printf("[-] Erro ao serializar resultados: %v\n", err)
		return
	}
	if err := os.WriteFile(saida, dados, 0644); err != nil {
		fmt.Printf("[-] Erro ao salvar %s: %v\n", saida, err)
		return
	}

	atrasDeCDN := 0
	for _, r := range resultado {
		if r.EhCDN {
			atrasDeCDN++
		}
	}
	fmt.Printf("[+] Classificação de CDN concluída: %d/%d host(s) atrás de CDN. Salvo em %s\n",
		atrasDeCDN, len(resultado), saida)
}
