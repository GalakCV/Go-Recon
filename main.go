package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	rv1crawling "go-recon/rv1-crawling"
	rv1js "go-recon/rv1-js"
	rv1jsanalise "go-recon/rv1-js-analise"
	rv1recongeral "go-recon/rv1-recongeral"
	rv1subdominios "go-recon/rv1-subdominios"
	rv1validacao "go-recon/rv1-validacao"
	// rv1tecnologia removido: tech-detect agora vem do httpx -td (rv1-recongeral).
	rv1db "go-recon/database_create"
	recondash "go-recon/recon-dash"
	rv1admin "go-recon/rv1-admin"
	rv1cdn "go-recon/rv1-cdn"
	rv1cloud "go-recon/rv1-cloud"
	rv1disclosure "go-recon/rv1-disclosure"
)

// etapaTimeoutPadrao é um teto de segurança aplicado a CADA etapa do
// pipeline. Antes, o contexto de cada etapa só era cancelado via CTRL + C
// (context.WithCancel sem prazo), então qualquer ferramenta externa que
// travasse (ex: katana numa lista grande de hosts, sem flags de limite)
// prendia o pipeline indefinidamente. Agora, se o usuário esquecer de
// apertar CTRL + C, a etapa é cancelada sozinha depois desse tempo e o
// pipeline segue para a próxima.
const etapaTimeoutPadrao = 30 * time.Minute

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
		{
			nome: "Subdomínios (subfinder + puredns bruteforce)",
			fn:   func(ctx context.Context) { rv1subdominios.Subdominios(ctx, arquivoAlvos, nomeEmpresa) },
		},
		{
			nome: "Resolução de Subdomínios (puredns/dnsx)",
			fn:   func(ctx context.Context) { rv1subdominios.ResolucaoSubdominios(ctx, nomeEmpresa) },
		},
		{
			nome: "Probe HTTP rico (httpx -json: status/title/tech/server)",
			fn:   func(ctx context.Context) { rv1recongeral.HttpxStatus(ctx, nomeEmpresa) },
		},
		// Crawling histórico (gau/waymore/xnLinkFinder) roda ANTES da coleta
		// de JS para que o ColetarJS consiga enxergar essas fontes salvas.
		{
			nome: "Crawling histórico (Gau)",
			fn:   func(ctx context.Context) { rv1crawling.Gau(ctx, nomeEmpresa) },
		},
		{
			nome: "Crawling histórico (Waymore)",
			fn:   func(ctx context.Context) { rv1crawling.Waymore(ctx, arquivoAlvos, nomeEmpresa) },
		},
		{
			nome: "Crawling histórico (XnLinkFinder)",
			fn:   func(ctx context.Context) { rv1crawling.XnLinkFinder(ctx, arquivoAlvos, nomeEmpresa) },
		},
		{
			nome: "Coleta de JavaScript (katana + histórico)",
			fn:   func(ctx context.Context) { rv1js.ColetarJS(ctx, nomeEmpresa) },
		},
		{
			nome: "Priorização de JavaScript (tiers HIGH/MEDIUM/LOW/SKIP)",
			fn:   func(ctx context.Context) { rv1js.PriorizarJS(ctx, nomeEmpresa) },
		},
		{
			nome: "Download seletivo de JavaScript",
			fn:   func(ctx context.Context) { rv1jsanalise.BaixarJS(ctx, nomeEmpresa) },
		},
		{
			nome: "Extração de Endpoints (jsluice + jshunter + linkfinder)",
			fn:   func(ctx context.Context) { rv1jsanalise.ExtrairEndpoints(ctx, arquivoAlvos, nomeEmpresa) },
		},
		{
			nome: "Validação de Endpoints (httpx direcionado)",
			fn:   func(ctx context.Context) { rv1jsanalise.ValidarEndpoints(ctx, nomeEmpresa) },
		},
		{
			nome: "Análise de Segredos (trufflehog + gitleaks)",
			fn:   func(ctx context.Context) { rv1jsanalise.AnalisarSegredos(ctx, nomeEmpresa) },
		},
		// ------------------------------------------------------------------
		// Nota: a descoberta de tecnologias deixou de ser uma etapa própria
		// (webanalyze). O httpx -td já traz o tech-detect por host no
		// http/httpx.jsonl, numa requisição que o pipeline faz de qualquer
		// forma — uma ferramenta a menos para o mesmo sinal.
		{
			nome: "Vetores de Ataque (triagem + validação + confirmação)",
			fn:   func(ctx context.Context) { rv1validacao.ProcessarVetores(ctx, arquivoAlvos, nomeEmpresa) },
		},
		{
			nome: "Admin Panel Finder (fingerprint via baseline 404)",
			fn:   func(ctx context.Context) { rv1admin.EncontrarAdminPanels(ctx, nomeEmpresa) },
		},
		{
			nome: "Disclosure Scanner (Spring Boot Actuator + GraphQL)",
			fn:   func(ctx context.Context) { rv1disclosure.EscanearDisclosure(ctx, nomeEmpresa) },
		},
		{
			// testarEscrita=false por padrão: só LIST é testado (passivo).
			nome: "Cloud Recon (extração + teste de permissão real)",
			fn:   func(ctx context.Context) { rv1cloud.CloudRecon(ctx, nomeEmpresa, false) },
		},
		{
			nome: "Classificação de CDN por IP",
			fn:   func(ctx context.Context) { rv1cdn.FiltrarCDN(ctx, nomeEmpresa) },
		},
		{
			// Exportação pro SQLite vem por ÚLTIMO de propósito: precisa
			// rodar DEPOIS de todas as etapas que geram arquivo (admin,
			// disclosure, cloud, cdn, js), senão o banco fica sem esses
			// achados até a próxima execução.
			nome: "Exportação para Banco de Dados SQLite",
			fn:   func(ctx context.Context) { rv1db.PopularBanco(ctx, nomeEmpresa) },
		},
	}

	for _, etapa := range etapas {
		ctx, cancel := context.WithTimeout(context.Background(), etapaTimeoutPadrao)
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
		if ctx.Err() == context.DeadlineExceeded {
			fmt.Printf("[!] Etapa \"%s\" excedeu o tempo máximo (%s) e foi encerrada automaticamente.\n", etapa.nome, etapaTimeoutPadrao)
		}
		signal.Stop(sigChan)
		cancel()
	}

	fmt.Println("\n[+] Pipeline de reconhecimento finalizada com sucesso!")
	recondash.IniciarDashboard(nomeEmpresa, "8888")
}
