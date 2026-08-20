package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("Uso correto: %s <Alvos.txt> <Nome_da_Empresa>\n", os.Args[0])
		os.Exit(1)
	}
	arquivoAlvos := os.Args[1]
	nomeEmpresa := os.Args[2]

	CriarAmbiente(nomeEmpresa)
	fmt.Printf("[*] Lendo alvos do arquivo: %s\n", arquivoAlvos)

	// 1. Etapa de Subdomínios
	Subdominios(arquivoAlvos, nomeEmpresa)

	// 2. Etapa de Resolução de Subdomínios com dnsx
	ResolucaoSubdominios(nomeEmpresa)

	// 3. Etapa de Validação Web com Httpx (Completo com tecnologia e jq)
	Httpx(nomeEmpresa)

	// 4. Etapa de Verificação Rápida de Status Code com Httpx
	HttpxStatus(nomeEmpresa)
}

func CriarAmbiente(empresa string) {
	dirName := filepath.Clean(empresa)
	err := os.MkdirAll(dirName, 0755)
	if err != nil {
		fmt.Printf("[-] Erro ao criar o diretório '%s': %v\n", dirName, err)
		os.Exit(1)
	}
	fmt.Printf("[+] Pasta de ambiente criada com sucesso: ./%s/\n", dirName)
	os.MkdirAll(filepath.Join(dirName, "resultados"), 0755)
}

func Subdominios(arquivoAlvos string, empresa string) {
	fmt.Println("[+] Buscando subdomínios com Subfinder...")

	outputFile := filepath.Join(empresa, "resultados", "subdominios.txt")

	cmd := exec.Command("subfinder", "-dL", arquivoAlvos, "-o", outputFile, "-silent", "-all")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		fmt.Printf("[-] Erro ao executar o subfinder: %v\n", err)
		return
	}
	fmt.Printf("[+] Subdomínios salvos em: %s\n", outputFile)
}

func ResolucaoSubdominios(empresa string) {
	fmt.Println("[+] Realizando resolução de subdomínios com dnsx...")

	inputFile := filepath.Join(empresa, "resultados", "subdominios.txt")
	outputFile := filepath.Join(empresa, "resultados", "resolvidos.txt")

	cmd := exec.Command("dnsx", "-l", inputFile, "-t", "200", "-retry", "2", "-o", outputFile, "-silent")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		fmt.Printf("[-] Erro ao executar o dnsx: %v\n", err)
		return
	}
	fmt.Printf("[+] Subdomínios resolvidos salvos em: %s\n", outputFile)
}

func Httpx(empresa string) {
	fmt.Println("[+] Executando o httpx para validação de hosts web (tecnologias e detalhes)...")

	inputFile := filepath.Join(empresa, "resultados", "resolvidos.txt")
	outputFile := filepath.Join(empresa, "resultados", "httpx.txt")

	cmd := exec.Command("httpx", 
		"-l", inputFile, 
		"-silent", 
		"-timeout", "10", 
		"-json", 
		"-sc", 
		"-td", 
		"-title", 
		"-server", 
		"-location", 
		"-cl", 
		"-tls-probe", 
		"-o", outputFile,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		fmt.Printf("[-] Erro ao executar o httpx: %v\n", err)
		return
	}

	tempFile := outputFile + ".tmp"
	jqCmd := exec.Command("jq", "-s", ".", outputFile)
	
	outFile, err := os.Create(tempFile)
	if err != nil {
		fmt.Printf("[-] Erro ao criar arquivo temporário: %v\n", err)
		return
	}
	jqCmd.Stdout = outFile
	jqCmd.Stderr = os.Stderr

	err = jqCmd.Run()
	outFile.Close()
	if err != nil {
		fmt.Printf("[-] Erro ao formatar com jq: %v\n", err)
		return
	}

	err = os.Rename(tempFile, outputFile)
	if err != nil {
		fmt.Printf("[-] Erro ao atualizar o arquivo final: %v\n", err)
		return
	}

	fmt.Printf("[+] Resultados do httpx formatados em JSON salvos em: %s\n", outputFile)
}

func HttpxStatus(empresa string) {
	fmt.Println("[+] Executando o httpx para verificação rápida de Status Code...")

	inputFile := filepath.Join(empresa, "resultados", "resolvidos.txt")
	outputFile := filepath.Join(empresa, "resultados", "statuscode-httpx.txt")

	cmd := exec.Command("httpx", 
		"-l", inputFile, 
		"-silent", 
		"-sc", 
		"-o", outputFile,
	)
	
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		fmt.Printf("[-] Erro ao executar o httpx de status code: %v\n", err)
		return
	}
	fmt.Printf("[+] Status codes salvos em: %s\n", outputFile)
}
