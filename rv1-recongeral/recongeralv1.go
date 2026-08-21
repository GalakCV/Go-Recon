package rv1recongeral

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func HttpxStatus(ctx context.Context, empresa string) {
	fmt.Println("[+] Executando o httpx para verificação rápida de Status Code...")

	inputFile := filepath.Join(empresa, "resultados", "resolvidos.txt")
	outputFile := filepath.Join(empresa, "resultados", "statuscode-httpx.txt")

	// Usando CommandContext para permitir o cancelamento pelo CTRL+C
	cmd := exec.CommandContext(ctx, "httpx",
		"-l", inputFile,
		"-silent",
		"-sc",
		"-o", outputFile,
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.Canceled {
			fmt.Println("\n[!] Httpx Status cancelado pelo usuário (CTRL + C). Avançando...")
			return
		}
		fmt.Printf("[-] Erro ao executar o httpx de status code: %v\n", err)
		return
	}

	fmt.Printf("[+] Status codes salvos em: %s\n", outputFile)

	outputFile2 := filepath.Join(empresa, "resultados", "status200.txt")
	file, err := os.Open(outputFile)
	if err != nil {
		fmt.Printf("[-] Erro ao abrir o arquivo de status codes: %v\n", err)
		return
	}
	defer file.Close()

	out2, err := os.Create(outputFile2)
	if err != nil {
		fmt.Printf("[-] Erro ao criar o arquivo status200.txt: %v\n", err)
		return
	}
	defer out2.Close()

	scanner := bufio.NewScanner(file)
	count := 0

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "200") {
			parts := strings.Fields(line)
			for _, part := range parts {
				if strings.HasPrefix(part, "http") {
					_, err := out2.WriteString(part + "\n")
					if err != nil {
						fmt.Printf("[-] Erro ao escrever no arquivo: %v\n", err)
					}
					count++
					break
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("[-] Erro ao ler o arquivo: %v\n", err)
		return
	}

	fmt.Printf("[+] %d domínios com status 200 salvos em: %s\n", count, outputFile2)
}