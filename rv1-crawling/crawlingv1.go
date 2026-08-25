package rv1crawling

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

// Gau roda o gau sobre os hosts de status200.txt (via stdin, um host por
// linha, sem scheme/path) e junta o resultado em urls.txt.
func Gau(ctx context.Context, empresa string) {
	fmt.Println("[+] Executando o gau...")

	resultadosDir := filepath.Join(empresa, "resultados")
	inputStatus200 := filepath.Join(resultadosDir, "status200.txt")
	outputGau := filepath.Join(resultadosDir, "gau.txt")
	urlsFile := filepath.Join(resultadosDir, "urls.txt")

	hosts, err := extrairHosts(inputStatus200)
	if err != nil {
		fmt.Printf("[-] Erro ao ler %s: %v\n", inputStatus200, err)
		return
	}
	if len(hosts) == 0 {
		fmt.Printf("[-] Nenhum host encontrado em %s\n", inputStatus200)
		return
	}

	// CORREÇÃO: Flag alterada de -o para --o de acordo com a sua versão do gau
	cmd := exec.CommandContext(ctx, "gau", "--o", outputGau)
	cmd.Stdin = strings.NewReader(strings.Join(hosts, "\n"))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.Canceled {
			fmt.Println("\n[!] Gau cancelado pelo usuário (CTRL + C). Avançando...")
			return
		}
		fmt.Printf("[-] Erro ao executar o gau: %v\n", err)
		return
	}

	novos, err := mergeParaUrls(outputGau, urlsFile)
	if err != nil {
		fmt.Printf("[-] Erro ao juntar resultado do gau em urls.txt: %v\n", err)
		return
	}
	fmt.Printf("[+] %d novas URLs do gau adicionadas em: %s\n", novos, urlsFile)
}

// Waymore roda o waymore em modo URL-only (-mode U) e junta o resultado em
// urls.txt.
func Waymore(ctx context.Context, arquivoAlvos, empresa string) {
	fmt.Println("[+] Executando o waymore...")

	resultadosDir := filepath.Join(empresa, "resultados")
	outputWaymore := filepath.Join(resultadosDir, "waymore.txt")
	urlsFile := filepath.Join(resultadosDir, "urls.txt")

	if _, err := os.Stat(arquivoAlvos); err != nil {
		fmt.Printf("[-] Arquivo de alvos não encontrado: %s\n", arquivoAlvos)
		return
	}

	cmd := exec.CommandContext(ctx, "waymore",
		"-i", arquivoAlvos,
		"-mode", "U",
		"-oU", outputWaymore,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.Canceled {
			fmt.Println("\n[!] Waymore cancelado pelo usuário (CTRL + C). Avançando...")
			return
		}
		fmt.Printf("[-] Erro ao executar o waymore: %v\n", err)
		return
	}

	novos, err := mergeParaUrls(outputWaymore, urlsFile)
	if err != nil {
		fmt.Printf("[-] Erro ao juntar resultado do waymore em urls.txt: %v\n", err)
		return
	}
	fmt.Printf("[+] %d novas URLs do waymore adicionadas em: %s\n", novos, urlsFile)
}

// XnLinkFinder roda o xnLinkFinder sobre status200.txt (arquivo de URLs) e
// junta o resultado em urls.txt.
// XnLinkFinder roda o xnLinkFinder sobre status200.txt (arquivo de URLs) e
// junta o resultado em urls.txt.
func XnLinkFinder(ctx context.Context, arquivoAlvos, empresa string) {
	fmt.Println("[+] Executando o xnLinkFinder...")

	resultadosDir := filepath.Join(empresa, "resultados")
	inputStatus200 := filepath.Join(resultadosDir, "status200.txt")
	outputXn := filepath.Join(resultadosDir, "xnlinkfinder.txt")
	urlsFile := filepath.Join(resultadosDir, "urls.txt")

	if _, err := os.Stat(inputStatus200); err != nil {
		fmt.Printf("[-] Arquivo não encontrado: %s\n", inputStatus200)
		return
	}

	// CORREÇÃO: Removido o -sp (não necessário aqui) e alterado o -sf para usar
	// diretamente a variável 'empresa' (ex: "google") como string de filtro.
	cmd := exec.CommandContext(ctx, "xnLinkFinder",
		"-i", inputStatus200,
		"-sf", empresa,
		"-o", outputXn,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.Canceled {
			fmt.Println("\n[!] XnLinkFinder cancelado pelo usuário (CTRL + C). Avançando...")
			return
		}
		fmt.Printf("[-] Erro ao executar o xnLinkFinder: %v\n", err)
		return
	}

	novos, err := mergeParaUrls(outputXn, urlsFile)
	if err != nil {
		fmt.Printf("[-] Erro ao juntar resultado do xnLinkFinder em urls.txt: %v\n", err)
		return
	}
	fmt.Printf("[+] %d novas URLs do xnLinkFinder adicionadas em: %s\n", novos, urlsFile)
}

// extrairHosts lê um arquivo de URLs (uma por linha) e retorna a lista de
// hosts únicos (sem scheme, sem path), no formato que o gau espera.
func extrairHosts(caminho string) ([]string, error) {
	arquivo, err := os.Open(caminho)
	if err != nil {
		return nil, err
	}
	defer arquivo.Close()

	vistos := make(map[string]struct{})
	var hosts []string

	scanner := bufio.NewScanner(arquivo)
	for scanner.Scan() {
		linha := strings.TrimSpace(scanner.Text())
		if linha == "" {
			continue
		}

		u, err := url.Parse(linha)
		host := linha
		if err == nil && u.Hostname() != "" {
			host = u.Hostname()
		}

		if _, existe := vistos[host]; existe {
			continue
		}
		vistos[host] = struct{}{}
		hosts = append(hosts, host)
	}

	return hosts, scanner.Err()
}

// mergeParaUrls lê o arquivo de origem linha a linha e acrescenta em
// destino (urls.txt) só as linhas que ainda não existem lá, deduplicando
// contra o conteúdo já presente. Retorna quantas linhas novas foram
// adicionadas.
func mergeParaUrls(origem, destino string) (int, error) {
	existentes := make(map[string]struct{})

	if existente, err := os.Open(destino); err == nil {
		scanner := bufio.NewScanner(existente)
		scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)
		for scanner.Scan() {
			existentes[strings.TrimSpace(scanner.Text())] = struct{}{}
		}

		// CORREÇÃO: Validação de erro do scanner no loop de leitura do arquivo existente
		if err := scanner.Err(); err != nil {
			existente.Close()
			return 0, fmt.Errorf("erro ao ler o arquivo de destino existente: %v", err)
		}

		existente.Close()
	}

	src, err := os.Open(origem)
	if err != nil {
		return 0, err
	}
	defer src.Close()

	out, err := os.OpenFile(destino, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return 0, err
	}
	defer out.Close()

	writer := bufio.NewWriter(out)
	defer writer.Flush()

	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)

	var novos int
	for scanner.Scan() {
		linha := strings.TrimSpace(scanner.Text())
		if linha == "" {
			continue
		}
		if _, existe := existentes[linha]; existe {
			continue
		}
		existentes[linha] = struct{}{}
		if _, err := writer.WriteString(linha + "\n"); err != nil {
			return novos, err
		}
		novos++
	}

	return novos, scanner.Err()
}
