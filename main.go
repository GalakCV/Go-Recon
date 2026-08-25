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
	//"go-recon/rv1-js-analise"
	//"go-recon/rv1-crawling"
	//rv1tecnologia "go-recon/rv1-tecnologia"
	//go-recon/rv1-validacao"
	//"go-recon/database_create"
	"go-recon/recon-dash"
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
			},
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
			{
				nome:"Realizando crawling com Gau",
				fn:   func(ctx context.Context) {rv1crawling.Gau(ctx, nomeEmpresa)},
			},
			{
				nome:"Realizando crawling com Waymore",
				fn:   func(ctx context.Context) {rv1crawling.Waymore(ctx, arquivoAlvos, nomeEmpresa)},
			},
			{
				nome:"Realizando crawling com Gau",
				fn:   func(ctx context.Context) {rv1crawling.XnLinkFinder(ctx,arquivoAlvos, nomeEmpresa)},
			},
		
		{
			nome: "Descoberta de Tecnologias (Webanalyze)",
			fn:   func(ctx context.Context) { rv1tecnologia.WebanalyzeTech(ctx, nomeEmpresa) },
		},
		{
			nome: "Purificação e Separação de Vetores (Uro + GF)",
			fn:   func(ctx context.Context) { rv1validacao.ProcessarVetores(ctx, nomeEmpresa) }, 
		},
		
		{
			nome: "Exportação para Banco de Dados SQLite",
			fn:   func(ctx context.Context) { rv1db.PopularBanco(ctx, nomeEmpresa) },

		},
		*/
	
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
	recondash.IniciarDashboard(nomeEmpresa, "8888")
}
