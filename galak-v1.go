package main

import (
	"fmt"
	"os"
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
}

func CriarAmbiente(empresa string) {
	dirName := filepath.Clean(empresa)
	err := os.MkdirAll(dirName, 0755)
	if err != nil {
		fmt.Printf("[-] Erro ao criar o diretório '%s': %v\n", dirName, err)
		os.Exit(1)
	}

	fmt.Printf("[+] Pasta de ambiente criada com sucesso: ./%s/\n", dirName)
	os.MkdirAll(filepath.Join(dirName, "output"), 0755)
}

func Subdominios(){
	
}
