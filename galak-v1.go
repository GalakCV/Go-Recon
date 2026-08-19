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

	// Chamando a função de subdomínios passando o arquivo e a empresa
	Subdominios(arquivoAlvos, nomeEmpresa)
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

	// Define o caminho de saída para salvar os subdomínios dentro da pasta da empresa
	outputFile := filepath.Join(empresa, "resultados", "subdomains.txt")

	// Monta o comando usando a flag -dL para ler a lista de domínios e -o para o arquivo de saída
	cmd := exec.Command("subfinder", "-dL", arquivoAlvos, "-o", outputFile, "-silent", "-all")

	// Executa e direciona a saída padrão para o terminal também (opcional)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		fmt.Printf("[-] Erro ao executar o subfinder: %v\n", err)
		return
	}
	fmt.Printf("[+] Subdomínios salvos em: %s\n", outputFile)
}
