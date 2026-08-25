package rv1tecnologia

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// WebanalyzeTech executa o webanalyze sobre a lista de resolvidos.txt para descobrir
// tecnologias e salva o output filtrado em formato JSON.
func WebanalyzeTech(ctx context.Context, empresa string) {
	fmt.Println("[+] Atualizando base de assinaturas do webanalyze...")
	
	// É boa prática atualizar o banco de dados de tecnologias antes de rodar
	updateCmd := exec.CommandContext(ctx, "webanalyze", "-update")
	_ = updateCmd.Run() // Ignoramos o erro aqui pois o banco já pode estar atualizado

	fmt.Println("[+] Executando o webanalyze para descoberta de tecnologias...")

	resultadosDir := filepath.Join(empresa, "resultados")
	inputResolvidos := filepath.Join(resultadosDir, "resolvidos.txt")
	outputTech := filepath.Join(resultadosDir, "tecnologias.json")

	if _, err := os.Stat(inputResolvidos); err != nil {
		fmt.Printf("[-] Arquivo de entrada não encontrado: %s\n", inputResolvidos)
		return
	}

	// Como o webanalyze não tem flag -o para arquivo, criamos o arquivo no Go
	// e redirecionamos o Stdout (saída padrão) direto para ele.
	outFile, err := os.Create(outputTech)
	if err != nil {
		fmt.Printf("[-] Erro ao criar arquivo de saída: %v\n", err)
		return
	}
	defer outFile.Close()

	cmd := exec.CommandContext(ctx, "webanalyze",
		"-hosts", inputResolvidos,
		"-worker", "30",   // Concorrência ajustada para não travar
		"-output", "json", // Formato de saída
		"-silent",         // Evita imprimir banners e logs no meio do JSON
	)
	
	cmd.Stdout = outFile // Joga o JSON diretamente para o arquivo
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.Canceled {
			fmt.Println("\n[!] Webanalyze cancelado pelo usuário (CTRL + C). Avançando...")
			return
		}
		fmt.Printf("[-] Erro ao executar o webanalyze: %v\n", err)
		return
	}

	// Garantir que o arquivo foi escrito antes de rodar o jq
	outFile.Sync()

	fmt.Println("[+] Aplicando filtro e formatação com jq...")
	
	// CORREÇÃO: Usamos o jq para mapear o JSON bruto e extrair apenas a URL e as tecnologias,
	// retornando um array JSON limpo (-s).
	jqFiltro := `jq -s '[.[] | {url: .hostname, tecnologias: [.matches[].app_name]}]'`
	jqCmdStr := fmt.Sprintf("%s %s > %s.tmp && mv %s.tmp %s", jqFiltro, outputTech, outputTech, outputTech, outputTech)
	
	jqCmd := exec.CommandContext(ctx, "sh", "-c", jqCmdStr)
	
	if err := jqCmd.Run(); err != nil {
		fmt.Printf("[-] Erro ao formatar com jq (certifique-se que o jq está instalado): %v\n", err)
	} else {
		fmt.Printf("[+] Saída limpa, formatada e salva em: %s\n", outputTech)
	}
}