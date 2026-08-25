package rv1validacao
import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// ProcessarVetores limpa arquivos temporários, purifica as URLs com o Uro
// e separa a superfície de ataque por vulnerabilidade usando o gf.
func ProcessarVetores(ctx context.Context, empresa string) {
	fmt.Println("\n[+] Iniciando etapa de purificação e separação de vetores...")

	resultadosDir := filepath.Join(empresa, "resultados")
	urlsTxt := filepath.Join(resultadosDir, "urls.txt")
	urls02Txt := filepath.Join(resultadosDir, "urls02.txt")
	vetoresDir := filepath.Join(resultadosDir, "vetores_ataque")

	// 1. Limpeza dos arquivos temporários
	fmt.Println("[*] Limpando arquivos temporários brutos...")
	lixos := []string{"gau.txt", "jshunter.txt", "waymore.txt", "xnlinkfinder.txt"}
	for _, lixo := range lixos {
		caminho := filepath.Join(resultadosDir, lixo)
		_ = os.Remove(caminho) // Remove e ignora o erro caso o arquivo não exista
	}

	// 2. Purificação com Uro
	fmt.Println("[*] Executando Uro para deduplicar e purificar URLs...")
	// Usamos sh -c para replicar exatamente o comportamento do seu pipe (cat | uro)
	uroCmdStr := fmt.Sprintf("cat %s | uro > %s", urlsTxt, urls02Txt)
	uroCmd := exec.CommandContext(ctx, "sh", "-c", uroCmdStr)
	uroCmd.Stderr = os.Stderr // Caso o Uro reclame de algo
	
	if err := uroCmd.Run(); err != nil {
		if ctx.Err() == context.Canceled {
			fmt.Println("\n[!] Processo do Uro cancelado pelo usuário.")
			return
		}
		fmt.Printf("[-] Erro ao executar o Uro: %v\n", err)
		return
	}

	// 3. Criação da pasta para os vetores
	if err := os.MkdirAll(vetoresDir, 0755); err != nil {
		fmt.Printf("[-] Erro ao criar a pasta de vetores: %v\n", err)
		return
	}

	// 4. Separação de parâmetros com o GF
	fmt.Println("[*] Extraindo padrões de vulnerabilidade com GF...")
	padroes := []string{"xss", "sqli", "lfi", "ssrf", "idor", "redirect", "rce", "ssti", "lfi-os", "cors"}

	for _, padrao := range padroes {
		select {
		case <-ctx.Done():
			fmt.Println("\n[!] Separação com GF cancelada pelo usuário.")
			return
		default:
		}

		arquivoSaida := filepath.Join(vetoresDir, padrao+".txt")

		// Prepara o comando do gf
		gfCmd := exec.CommandContext(ctx, "gf", padrao, urls02Txt)
		
		// O buffer vai capturar tudo o que o gf imprimir no terminal
		var out bytes.Buffer
		gfCmd.Stdout = &out

		// O gf retorna um exit code de erro (status 1) se não encontrar nenhum match.
		// Por isso, nós rodamos o comando e ignoramos o erro propositalmente.
		_ = gfCmd.Run()

		// Pegamos os dados do buffer
		conteudo := out.Bytes()

		// Conta a quantidade de quebras de linha para simular o seu `wc -l`
		linhas := bytes.Count(conteudo, []byte("\n"))

		// Salva no arquivo .txt apenas se encontrou alguma URL
		if linhas > 0 {
			if err := os.WriteFile(arquivoSaida, conteudo, 0644); err != nil {
				fmt.Printf("[-] Erro ao salvar %s: %v\n", arquivoSaida, err)
				continue
			}
			fmt.Printf("[+] Arquivo gerado: %s com %d URLs\n", arquivoSaida, linhas)
		} else {
			// Se estiver vazio, não poluímos a pasta com arquivos 0 bytes
			fmt.Printf("[-] Nenhum padrão encontrado para: %s\n", padrao)
		}
	}

	fmt.Println("[+] Purificação e separação de vetores finalizada com sucesso!")
}