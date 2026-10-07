package rv1subdominios

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// Descoberta e resolução de subdomínios.
//
// Fluxo:
//   subfinder (passivo)  ─┐
//   puredns bruteforce   ─┤→ subdominios.txt (união, dedup)
//                         │
//   puredns resolve  ────────→ resolvidos.txt (só o que resolve DNS de verdade)
//
// Config por ambiente (todas opcionais, com default):
//   GORECON_RESOLVERS  caminho do resolvers.txt (default: ./resolvers.txt)
//   GORECON_WORDLIST   wordlist de bruteforce   (default: ./wordlist.txt)
//
// Sem puredns/resolvers/wordlist a etapa degrada graciosamente: cai para
// dnsx (resolução) e pula o bruteforce, sempre avisando o que foi pulado.
// ---------------------------------------------------------------------------

func hasTool(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func fileExiste(caminho string) bool {
	_, err := os.Stat(caminho)
	return err == nil
}

// resolversPath devolve o caminho do resolvers.txt (env ou default) se existir.
func resolversPath() string {
	p := strings.TrimSpace(os.Getenv("GORECON_RESOLVERS"))
	if p == "" {
		p = "resolvers.txt"
	}
	if fileExiste(p) {
		return p
	}
	return ""
}

// wordlistPath devolve o caminho da wordlist de bruteforce (env ou default).
func wordlistPath() string {
	p := strings.TrimSpace(os.Getenv("GORECON_WORDLIST"))
	if p == "" {
		p = "wordlist.txt"
	}
	if fileExiste(p) {
		return p
	}
	return ""
}

// lerLinhas lê um arquivo e devolve as linhas não vazias, trimadas.
func lerLinhas(caminho string) []string {
	f, err := os.Open(caminho)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// escreverUnicas grava linhas únicas e ordenadas num arquivo.
func escreverUnicas(caminho string, linhas []string) (int, error) {
	visto := make(map[string]struct{}, len(linhas))
	var unicas []string
	for _, l := range linhas {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if _, ok := visto[l]; ok {
			continue
		}
		visto[l] = struct{}{}
		unicas = append(unicas, l)
	}
	sort.Strings(unicas)

	f, err := os.Create(caminho)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, l := range unicas {
		w.WriteString(l)
		w.WriteByte('\n')
	}
	return len(unicas), w.Flush()
}

// Subdominios descobre subdomínios por fonte passiva (subfinder) e, quando
// há wordlist + resolvers, por bruteforce DNS (puredns), unindo tudo em
// subdominios.txt (dedup).
func Subdominios(ctx context.Context, arquivoAlvos string, empresa string) {
	fmt.Println("[+] Descoberta de subdomínios (subfinder passivo + puredns bruteforce)...")

	resultadosDir := filepath.Join(empresa, "resultados")
	if err := os.MkdirAll(resultadosDir, 0755); err != nil {
		fmt.Printf("[-] Erro criando diretório de resultados: %v\n", err)
		return
	}
	outSubfinder := filepath.Join(resultadosDir, "subfinder.txt")
	outBrute := filepath.Join(resultadosDir, "puredns-brute.txt")
	outFinal := filepath.Join(resultadosDir, "subdominios.txt")

	var todos []string

	// 1. subfinder — passivo, várias fontes (-all).
	if hasTool("subfinder") {
		cmd := exec.CommandContext(ctx, "subfinder",
			"-dL", arquivoAlvos,
			"-all",
			"-silent",
			"-o", outSubfinder,
		)
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			if ctx.Err() == context.Canceled {
				fmt.Println("\n[!] Subfinder cancelado (CTRL + C). Avançando...")
			} else {
				fmt.Printf("[-] Erro no subfinder: %v\n", err)
			}
		}
		todos = append(todos, lerLinhas(outSubfinder)...)
		fmt.Printf("[*] subfinder: %d subdomínio(s).\n", len(lerLinhas(outSubfinder)))
	} else {
		fmt.Println("[!] subfinder não encontrado — descoberta passiva pulada.")
	}

	// 2. puredns bruteforce — ativo, precisa de wordlist + resolvers.
	resolvers := resolversPath()
	wordlist := wordlistPath()
	switch {
	case !hasTool("puredns"):
		fmt.Println("[!] puredns não encontrado — bruteforce de subdomínio pulado.")
	case resolvers == "":
		fmt.Println("[!] resolvers.txt ausente (GORECON_RESOLVERS) — bruteforce pulado.")
	case wordlist == "":
		fmt.Println("[!] wordlist.txt ausente (GORECON_WORDLIST) — bruteforce pulado.")
	default:
		// puredns roda um domínio por vez; itera sobre os alvos raiz.
		dominios := lerLinhas(arquivoAlvos)
		var brutos []string
		for _, d := range dominios {
			select {
			case <-ctx.Done():
				fmt.Println("\n[!] Bruteforce cancelado (CTRL + C). Avançando...")
				break
			default:
			}
			d = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), "*.")
			if d == "" || strings.HasPrefix(d, "#") {
				continue
			}
			perDomainOut := outBrute + "." + d
			cmd := exec.CommandContext(ctx, "puredns", "bruteforce", wordlist, d,
				"-r", resolvers,
				"--quiet",
				"-w", perDomainOut,
			)
			cmd.Stderr = os.Stderr
			_ = cmd.Run()
			brutos = append(brutos, lerLinhas(perDomainOut)...)
			_ = os.Remove(perDomainOut)
		}
		_, _ = escreverUnicas(outBrute, brutos)
		todos = append(todos, brutos...)
		fmt.Printf("[*] puredns bruteforce: %d subdomínio(s).\n", len(brutos))
	}

	if len(todos) == 0 {
		fmt.Println("[-] Nenhum subdomínio descoberto. Abortando etapa.")
		return
	}

	n, err := escreverUnicas(outFinal, todos)
	if err != nil {
		fmt.Printf("[-] Erro ao gravar %s: %v\n", outFinal, err)
		return
	}
	fmt.Printf("[+] %d subdomínio(s) único(s) em: %s\n", n, outFinal)
}

// ResolucaoSubdominios filtra subdominios.txt para apenas os que resolvem DNS,
// gravando resolvidos.txt. Prefere puredns resolve (rápido, usa os resolvers
// validados); cai para dnsx quando puredns não está disponível.
func ResolucaoSubdominios(ctx context.Context, empresa string) {
	fmt.Println("[+] Resolução DNS dos subdomínios...")

	resultadosDir := filepath.Join(empresa, "resultados")
	inputFile := filepath.Join(resultadosDir, "subdominios.txt")
	outputFile := filepath.Join(resultadosDir, "resolvidos.txt")

	if !fileExiste(inputFile) {
		fmt.Printf("[-] %s não encontrado — rode a descoberta antes.\n", inputFile)
		return
	}

	resolvers := resolversPath()

	// 1. puredns resolve (preferido): valida contra resolvers confiáveis e
	// derruba wildcard DNS automaticamente — menos falso positivo de host.
	if hasTool("puredns") && resolvers != "" {
		cmd := exec.CommandContext(ctx, "puredns", "resolve", inputFile,
			"-r", resolvers,
			"--quiet",
			"-w", outputFile,
		)
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			if ctx.Err() == context.Canceled {
				fmt.Println("\n[!] puredns resolve cancelado (CTRL + C). Avançando...")
				return
			}
			fmt.Printf("[-] Erro no puredns resolve: %v\n", err)
			// não retorna: tenta dnsx como fallback abaixo
		} else {
			fmt.Printf("[+] %d host(s) resolvido(s) em: %s\n", len(lerLinhas(outputFile)), outputFile)
			return
		}
	}

	// 2. dnsx (fallback). Usa resolvers próprios quando disponíveis.
	if !hasTool("dnsx") {
		fmt.Println("[!] dnsx não encontrado e puredns indisponível — resolução pulada.")
		return
	}
	args := []string{"-l", inputFile, "-t", "200", "-retry", "2", "-o", outputFile, "-silent"}
	if resolvers != "" {
		args = append(args, "-r", resolvers)
	} else {
		fmt.Println("[!] resolvers.txt ausente — dnsx vai usar o resolver do sistema (menos confiável).")
	}
	cmd := exec.CommandContext(ctx, "dnsx", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.Canceled {
			fmt.Println("\n[!] dnsx cancelado (CTRL + C). Avançando...")
			return
		}
		fmt.Printf("[-] Erro no dnsx: %v\n", err)
		return
	}
	fmt.Printf("[+] %d host(s) resolvido(s) em: %s\n", len(lerLinhas(outputFile)), outputFile)
}
