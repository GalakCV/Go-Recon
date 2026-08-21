package rv1jsanalise

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ExtrairEndpoints executa o jshunter sobre js-validos.txt e extrai todos os
// endpoints encontrados para resultados/urls.txt.
//
// IMPORTANTE: o jshunter, na versão testada, não produz JSON de verdade
// mesmo com --json — a saída real é texto no formato:
//
//	URL: https://site.com/app.js
//	ENDPOINT: https://site.com/api/x
//	ENDPOINT: https://site.com/api/y
//
// Por isso o parser abaixo trabalha em cima desse formato de texto, e não
// de um schema JSON. Se a sua versão do jshunter realmente emitir JSON
// estruturado com --json, esse parser vai simplesmente ignorar as linhas
// (nenhuma começa com "ENDPOINT:") e urls.txt sairá vazio — nesse caso
// avise para eu trocar para json.Unmarshal.
//
// Fluxo:
//
//	js-validos.txt
//	     ↓
//	jshunter -l -ep
//	     ↓
//	jshunter.txt (saída bruta)
//	     ↓
//	parser de linhas "ENDPOINT:"
//	     ↓
//	urls.txt (sem filtro, dedup só por segurança)
func ExtrairEndpoints(ctx context.Context, empresa string) {
	fmt.Println("[+] Executando o jshunter para extração de endpoints...")

	resultadosDir := filepath.Join(empresa, "resultados")
	inputJS := filepath.Join(resultadosDir, "js-validos.txt")
	outputBruto := filepath.Join(resultadosDir, "jshunter.txt")
	outputURLs := filepath.Join(resultadosDir, "urls.txt")

	if _, err := os.Stat(inputJS); err != nil {
		fmt.Printf("[-] Arquivo não encontrado: %s\n", inputJS)
		return
	}

	if err := os.MkdirAll(resultadosDir, 0755); err != nil {
		fmt.Printf("[-] Erro criando diretório de resultados: %v\n", err)
		return
	}

	// Flags confirmadas na documentação do jshunter: -l (lista), -ep
	// (extrair endpoints), -o (arquivo de saída), -q (sem ascii art).
	// Removido "--json"/"-s"/"-x"/"-F" por não constarem na doc oficial
	// e não baterem com o exemplo de saída real que você mandou — rode
	// "jshunter --help" na sua versão pra confirmar se elas existem.
	cmd := exec.CommandContext(ctx, "jshunter",
		"-l", inputJS,
		"-ep",
		"-q",
		"-o", outputBruto,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.Canceled {
			fmt.Println("\n[!] Jshunter cancelado pelo usuário (CTRL + C). Avançando...")
			return
		}
		fmt.Printf("[-] Erro ao executar o jshunter: %v\n", err)
		return
	}

	arquivoBruto, err := os.Open(outputBruto)
	if err != nil {
		fmt.Printf("[-] Erro ao abrir a saída do jshunter: %v\n", err)
		return
	}
	defer arquivoBruto.Close()

	saida, err := os.Create(outputURLs)
	if err != nil {
		fmt.Printf("[-] Erro ao criar %s: %v\n", outputURLs, err)
		return
	}
	defer saida.Close()

	writer := bufio.NewWriter(saida)
	defer writer.Flush()

	// Sem filtro/lógica de scope aqui de propósito (vai tudo pro banco
	// depois, filtragem fica pro HTML). Só evitamos duplicata idêntica
	// na mesma execução.
	vistos := make(map[string]struct{})
	scanner := bufio.NewScanner(arquivoBruto)

	var total int
	for scanner.Scan() {
		linha := strings.TrimSpace(scanner.Text())

		if !strings.HasPrefix(linha, "ENDPOINT:") {
			continue
		}

		endpoint := strings.TrimSpace(strings.TrimPrefix(linha, "ENDPOINT:"))
		if endpoint == "" {
			continue
		}

		if _, existe := vistos[endpoint]; existe {
			continue
		}
		vistos[endpoint] = struct{}{}

		if _, err := writer.WriteString(endpoint + "\n"); err != nil {
			fmt.Printf("[-] Erro escrevendo endpoint: %v\n", err)
			return
		}
		total++
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("[-] Erro lendo saída do jshunter: %v\n", err)
		return
	}

	fmt.Printf("[+] %d endpoints salvos em: %s\n", total, outputURLs)
}

func BaixarJS(ctx context.Context, empresa string) {
	fmt.Println("[+] Baixando arquivos JavaScript...")

	resultadosDir := filepath.Join(empresa, "resultados")
	inputJS := filepath.Join(resultadosDir, "js-validos.txt")
	jsDir := filepath.Join(resultadosDir, "javascripts")

	if _, err := os.Stat(inputJS); err != nil {
		fmt.Printf("[-] Arquivo não encontrado: %s\n", inputJS)
		return
	}

	if err := os.MkdirAll(jsDir, 0755); err != nil {
		fmt.Printf("[-] Erro criando diretório %s: %v\n", jsDir, err)
		return
	}

	arquivo, err := os.Open(inputJS)
	if err != nil {
		fmt.Printf("[-] Erro ao abrir %s: %v\n", inputJS, err)
		return
	}
	defer arquivo.Close()

	client := &http.Client{}

	var baixados, falhas int
	scanner := bufio.NewScanner(arquivo)

	for scanner.Scan() {

		select {
		case <-ctx.Done():
			fmt.Println("\n[!] Download de JS cancelado pelo usuário (CTRL + C). Avançando...")
			fmt.Printf("[+] %d arquivos baixados antes do cancelamento em: %s\n", baixados, jsDir)
			return
		default:
		}

		url := strings.TrimSpace(scanner.Text())
		if url == "" {
			continue
		}

		nomeArquivo := hashURL(url) + ".js"
		caminhoDestino := filepath.Join(jsDir, nomeArquivo)

		if err := baixarArquivo(ctx, client, url, caminhoDestino); err != nil {
			fmt.Printf("[-] Falha ao baixar %s: %v\n", url, err)
			falhas++
			continue
		}
		baixados++
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("[-] Erro lendo %s: %v\n", inputJS, err)
		return
	}

	fmt.Printf("[+] %d arquivos JS baixados em: %s\n", baixados, jsDir)
	if falhas > 0 {
		fmt.Printf("[!] %d downloads falharam.\n", falhas)
	}
}

func hashURL(url string) string {
	soma := sha1.Sum([]byte(url))
	return hex.EncodeToString(soma[:])
}

func baixarArquivo(ctx context.Context, client *http.Client, url, destino string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

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
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func AnalisarSegredos(ctx context.Context, empresa string) {
	fmt.Println("[+] Executando o trufflehog para busca de segredos...")

	resultadosDir := filepath.Join(empresa, "resultados")
	jsDir := filepath.Join(resultadosDir, "javascripts")
	outputFile := filepath.Join(resultadosDir, "segredos-trufflehog.json")

	entradas, err := os.ReadDir(jsDir)
	if err != nil || len(entradas) == 0 {
		fmt.Printf("[-] Nenhum arquivo JS encontrado em: %s (rode BaixarJS antes)\n", jsDir)
		return
	}

	outFile, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("[-] Erro ao criar %s: %v\n", outputFile, err)
		return
	}
	defer outFile.Close()

	cmd := exec.CommandContext(ctx, "trufflehog",
		"filesystem", jsDir,
		"--json",
		"--no-update",
	)
	cmd.Stdout = outFile
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.Canceled {
			fmt.Println("\n[!] Trufflehog cancelado pelo usuário (CTRL + C). Avançando...")
			return
		}
		fmt.Printf("[-] Erro ao executar o trufflehog: %v\n", err)
		return
	}

	fmt.Printf("[+] Resultado do trufflehog salvo em: %s\n", outputFile)
}