package rv1subdominios

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func Subdominios(ctx context.Context, arquivoAlvos string, empresa string) {
	fmt.Println("[+] Buscando subdomínios com Subfinder...")

	outputFile := filepath.Join(empresa, "resultados", "subdominios.txt")

	// Usamos CommandContext para que o CTRL + C mate o subfinder instantaneamente
	cmd := exec.CommandContext(ctx, "subfinder", "-dL", arquivoAlvos, "-o", outputFile, "-silent", "-all")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.Canceled {
			fmt.Println("\n[!] Subfinder cancelado pelo usuário (CTRL + C). Avançando...")
			return
		}
		fmt.Printf("[-] Erro ao executar o subfinder: %v\n", err)
		return
	}
	fmt.Printf("[+] Subdomínios salvos em: %s\n", outputFile)
}

func ResolucaoSubdominios(ctx context.Context, empresa string) {
	fmt.Println("[+] Realizando resolução de subdomínios com dnsx...")

	inputFile := filepath.Join(empresa, "resultados", "subdominios.txt")
	outputFile := filepath.Join(empresa, "resultados", "resolvidos.txt")

	cmd := exec.CommandContext(ctx, "dnsx", "-l", inputFile, "-t", "200", "-retry", "2", "-o", outputFile, "-silent")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.Canceled {
			fmt.Println("\n[!] Dnsx cancelado pelo usuário (CTRL + C). Avançando...")
			return
		}
		fmt.Printf("[-] Erro ao executar o dnsx: %v\n", err)
		return
	}
	fmt.Printf("[+] Subdomínios resolvidos salvos em: %s\n", outputFile)
}