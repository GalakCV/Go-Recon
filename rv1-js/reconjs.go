package rv1js

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const tamanhoMaximoScanner = 1024 * 1024

func ColetarJS(ctx context.Context, empresa string) {
	fmt.Println("[+] Executando o Katana para descoberta de JavaScript...")

	resultadosDir := filepath.Join(empresa, "resultados")
	inputURLs := filepath.Join(resultadosDir, "status200.txt")
	outputJS := filepath.Join(resultadosDir, "js-candidates.txt")

	// Verifica arquivo de entrada.
	if _, err := os.Stat(inputURLs); err != nil {
		fmt.Printf("[-] Arquivo não encontrado: %s\n", inputURLs)
		return
	}

	// Garante que o diretório exista.
	if err := os.MkdirAll(resultadosDir, 0755); err != nil {
		fmt.Printf("[-] Erro criando diretório de resultados: %v\n", err)
		return
	}

	cmd := exec.CommandContext(
		ctx,
		"katana",
		"-list", inputURLs,
		"-jc",
		"-silent",
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Printf("[-] Erro criando pipe do Katana: %v\n", err)
		return
	}

	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Printf("[-] Erro iniciando o Katana: %v\n", err)
		return
	}

	output, err := os.Create(outputJS)
	if err != nil {
		fmt.Printf("[-] Erro criando arquivo %s: %v\n", outputJS, err)

		_ = cmd.Process.Kill()
		_ = cmd.Wait()

		return
	}

	defer output.Close()

	writer := bufio.NewWriterSize(output, 64*1024)
	defer writer.Flush()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(
		make([]byte, 64*1024),
		tamanhoMaximoScanner,
	)

	visitadas := make(map[string]struct{})

	var total int
	var candidatas int
	var duplicadas int
	var invalidas int
	var infraestrutura int

	for scanner.Scan() {
		total++

		raw := strings.TrimSpace(scanner.Text())

		if raw == "" {
			continue
		}

		urlNormalizada, ok := normalizarURLJS(raw)

		if !ok {
			invalidas++
			continue
		}

		if ehInfraestruturaJS(urlNormalizada) {
			infraestrutura++
			continue
		}

		if _, existe := visitadas[urlNormalizada]; existe {
			duplicadas++
			continue
		}

		visitadas[urlNormalizada] = struct{}{}

		if _, err := writer.WriteString(urlNormalizada + "\n"); err != nil {
			fmt.Printf("[-] Erro escrevendo candidato JS: %v\n", err)
			return
		}

		candidatas++
	}

	if err := scanner.Err(); err != nil {
		if ctx.Err() == context.Canceled {
			fmt.Println("\n[!] Katana cancelado pelo usuário (CTRL + C). Avançando...")
			return
		}

		fmt.Printf("[-] Erro lendo saída do Katana: %v\n", err)

		_ = cmd.Process.Kill()
		_ = cmd.Wait()

		return
	}

	if err := cmd.Wait(); err != nil {
		if ctx.Err() == context.Canceled {
			fmt.Println("\n[!] Katana cancelado pelo usuário (CTRL + C). Avançando...")
			return
		}

		fmt.Printf("[-] Katana terminou com erro: %v\n", err)
		return
	}

	fmt.Println()
	fmt.Println("[+] Descoberta de JavaScript concluída.")
	fmt.Printf("[+] URLs recebidas: %d\n", total)
	fmt.Printf("[+] Candidatas JS: %d\n", candidatas)
	fmt.Printf("[+] Duplicatas removidas: %d\n", duplicadas)
	fmt.Printf("[+] URLs inválidas: %d\n", invalidas)
	fmt.Printf("[+] Infra/challenge removidos: %d\n", infraestrutura)
	fmt.Printf("[+] Salvo em: %s\n", outputJS)
}

func normalizarURLJS(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", false
	}

	// Somente HTTP/HTTPS.
	scheme := strings.ToLower(parsed.Scheme)

	if scheme != "http" && scheme != "https" {
		return "", false
	}

	if parsed.Host == "" {
		return "", false
	}

	caminho := strings.ToLower(parsed.Path)

	if !strings.HasSuffix(caminho, ".js") {
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

	path := strings.ToLower(parsed.Path)

	prefixos := []string{
		"/cdn-cgi/",
		"/challenge-platform/",
		"/captcha/",
		"/recaptcha/",
		"/hcaptcha/",
		"/turnstile/",
	}

	for _, prefixo := range prefixos {
		if strings.Contains(path, prefixo) {
			return true
		}
	}

	indicadores := []string{
		"challenge",
		"captcha",
		"turnstile",
		"recaptcha",
		"hcaptcha",
	}

	for _, indicador := range indicadores {
		if strings.Contains(path, indicador) {
			return true
		}
	}

	return false
}

// ValidarJS valida os candidatos utilizando o httpx.
//
// Fluxo:
//
//  js-candidates.txt
//       ↓
//  httpx
//       ↓
//  status 200
//       ↓
//  Content-Type JavaScript
//       ↓
//  page-type / error-page filtering
//       ↓
//  duplicatas de resposta removidas
//       ↓
//  js-validos.txt
func ValidarJS(ctx context.Context, empresa string) {
	fmt.Println("[+] Validando JavaScript ativo...")

	resultadosDir := filepath.Join(empresa, "resultados")

	inputJS := filepath.Join(
		resultadosDir,
		"js-candidates.txt",
	)

	outputValidJS := filepath.Join(
		resultadosDir,
		"js-validos.txt",
	)

	if _, err := os.Stat(inputJS); err != nil {
		fmt.Printf(
			"[-] Arquivo de candidatos não encontrado: %s\n",
			inputJS,
		)
		return
	}

	args := []string{
		"-l", inputJS,
		"-silent",
		"-mc", "200",
		"-ct",
		"-cl",
		"-fpt", "login,captcha,parked",
		"-fep",
		"-fd",
		"-H",
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	}

	cmd := exec.CommandContext(
		ctx,
		"httpx",
		args...,
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Printf("[-] Erro criando pipe do httpx: %v\n", err)
		return
	}

	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Printf("[-] Erro iniciando o httpx: %v\n", err)
		return
	}

	output, err := os.Create(outputValidJS)
	if err != nil {
		fmt.Printf(
			"[-] Erro criando arquivo %s: %v\n",
			outputValidJS,
			err,
		)

		_ = cmd.Process.Kill()
		_ = cmd.Wait()

		return
	}

	defer output.Close()

	writer := bufio.NewWriterSize(
		output,
		64*1024,
	)

	defer writer.Flush()

	scanner := bufio.NewScanner(stdout)

	scanner.Buffer(
		make([]byte, 64*1024),
		tamanhoMaximoScanner,
	)

	var testadas int
	var validos int
	var rejeitadosContentType int

	visitados := make(map[string]struct{})

	for scanner.Scan() {
		linha := strings.TrimSpace(scanner.Text())

		if linha == "" {
			continue
		}

		testadas++
		idx := strings.Index(linha, "[")

		if idx == -1 {
			continue
		}

		urlEncontrada := strings.TrimSpace(
			linha[:idx],
		)

		metadados := strings.ToLower(
			linha[idx:],
		)

		if urlEncontrada == "" {
			continue
		}
		if !contentTypeJavaScript(metadados) {
			rejeitadosContentType++
			continue
		}
		if ehInfraestruturaJS(urlEncontrada) {
			continue
		}

		if _, existe := visitados[urlEncontrada]; existe {
			continue
		}

		visitados[urlEncontrada] = struct{}{}

		if _, err := writer.WriteString(
			urlEncontrada + "\n",
		); err != nil {
			fmt.Printf(
				"[-] Erro escrevendo JS válido: %v\n",
				err,
			)
			return
		}

		validos++
	}

	if err := scanner.Err(); err != nil {
		if ctx.Err() == context.Canceled {
			fmt.Println(
				"\n[!] Httpx cancelado pelo usuário (CTRL + C). Avançando...",
			)
			return
		}

		fmt.Printf(
			"[-] Erro lendo saída do httpx: %v\n",
			err,
		)

		_ = cmd.Process.Kill()
		_ = cmd.Wait()

		return
	}

	if err := cmd.Wait(); err != nil {
		if ctx.Err() == context.Canceled {
			fmt.Println(
				"\n[!] Httpx cancelado pelo usuário (CTRL + C). Avançando...",
			)
			return
		}

		fmt.Printf(
			"[-] httpx terminou com erro: %v\n",
			err,
		)

		return
	}

	fmt.Println()
	fmt.Println("[+] Validação de JavaScript concluída.")
	fmt.Printf(
		"[+] Respostas HTTP 200 recebidas: %d\n",
		testadas,
	)
	fmt.Printf(
		"[+] JavaScript válidos: %d\n",
		validos,
	)
	fmt.Printf(
		"[+] Rejeitados por Content-Type: %d\n",
		rejeitadosContentType,
	)
	fmt.Printf(
		"[+] Salvo em: %s\n",
		outputValidJS,
	)
}

func contentTypeJavaScript(metadados string) bool {
	tipos := []string{
		"application/javascript",
		"text/javascript",
		"application/x-javascript",
		"application/ecmascript",
		"text/ecmascript",
	}

	for _, tipo := range tipos {
		if strings.Contains(metadados, tipo) {
			return true
		}
	}

	return false
}