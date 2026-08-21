package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	//"go-recon/rv1-js"
	//"go-recon/rv1-recongeral"
	//"go-recon/rv1-subdominios"
	"go-recon/rv1-js-analise"
)

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

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("Uso correto: %s <Alvos.txt> <Nome_da_Empresa>\n", os.Args[0])
		os.Exit(1)
	}
	arquivoAlvos := os.Args[1]
	nomeEmpresa := os.Args[2]

	CriarAmbiente(nomeEmpresa)
	fmt.Printf("[*] Lendo alvos do arquivo: %s\n", arquivoAlvos)
	fmt.Println("[*] Dica: Pressione CTRL + C para pular para a próxima etapa se necessário.")
	etapas := []struct {
		nome string
		fn   func(ctx context.Context)
	}{
		/*
		{
			nome: "Subdomínios (Subfinder)",
			fn:   func(ctx context.Context) { rv1subdominios.Subdominios(ctx, arquivoAlvos, nomeEmpresa) },
		},
		{
			nome: "Resolução de Subdomínios (Dnsx)",
			fn:   func(ctx context.Context) { rv1subdominios.ResolucaoSubdominios(ctx, nomeEmpresa) },
		},
		{
			nome: "Recon Geral Status (HttpxStatus)",
			fn:   func(ctx context.Context) { rv1recongeral.HttpxStatus(ctx, nomeEmpresa) },
		},
		{
			nome: "Coleta de JavaScript (Katana)",
			fn:   func(ctx context.Context) { rv1js.ColetarJS(ctx, nomeEmpresa) },
		},
		{
			nome: "Validação de JavaScript",
			fn:   func(ctx context.Context) { rv1js.ValidarJS(ctx, nomeEmpresa) },
		},*/
		{
			nome: "Extração de Endpoint",
			fn:   func(ctx context.Context) { rv1jsanalise.ExtrairEndpoints(ctx, nomeEmpresa) },
		},
		{
			nome: "Download de JavaScript",
			fn:   func(ctx context.Context) { rv1jsanalise.BaixarJS(ctx, nomeEmpresa) },
		},
		{
			nome: "Analise de secrets com Trufflehog",
			fn:   func(ctx context.Context) { rv1jsanalise.AnalisarSegredos(ctx, nomeEmpresa) },
		},
	}

	for _, etapa := range etapas {
		ctx, cancel := context.WithCancel(context.Background())
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGINT)
		go func() {
			<-sigChan
			cancel() 
		}()
		fmt.Printf("\n========================================\n")
		fmt.Printf("[*] Etapa: %s\n", etapa.nome)
		fmt.Printf("========================================\n")
		etapa.fn(ctx)
		signal.Stop(sigChan)
		cancel()
	}
	
	fmt.Println("\n[+] Pipeline de reconhecimento finalizada com sucesso!")
}