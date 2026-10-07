package rv1recongeral

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ---------------------------------------------------------------------------
// Probe HTTP rico (httpx -json).
//
// Uma requisição por host já paga por MUITO contexto, então pedimos tudo de
// uma vez: status, título, servidor, tecnologias, content-length, redirect.
// A saída JSONL (http/httpx.jsonl) vira a fonte única de "o que está vivo".
//
// Definição de "vivo" para recon web: 200,201,204,301,302,401,403,405.
// 401/403/405 contam de propósito — endpoint que existe e está protegido é
// exatamente o que interessa procurar depois (bypass, auth, verbo HTTP).
// ---------------------------------------------------------------------------

var statusVivos = map[int]bool{
	200: true, 201: true, 204: true,
	301: true, 302: true,
	401: true, 403: true, 405: true,
}

// linhaHttpx é o subconjunto do JSON do httpx que consumimos.
type linhaHttpx struct {
	URL           string   `json:"url"`
	Input         string   `json:"input"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title"`
	Webserver     string   `json:"webserver"`
	Tech          []string `json:"tech"`
	ContentLength int      `json:"content_length"`
	Location      string   `json:"location"`
}

func HttpxStatus(ctx context.Context, empresa string) {
	fmt.Println("[+] Probe HTTP rico (httpx -json: status, título, tech, server)...")

	resultadosDir := filepath.Join(empresa, "resultados")
	httpDir := filepath.Join(resultadosDir, "http")
	if err := os.MkdirAll(httpDir, 0755); err != nil {
		fmt.Printf("[-] Erro criando diretório http/: %v\n", err)
		return
	}

	inputFile := filepath.Join(resultadosDir, "resolvidos.txt")
	if _, err := os.Stat(inputFile); err != nil {
		fmt.Printf("[-] %s não encontrado — rode a resolução antes.\n", inputFile)
		return
	}

	if _, err := exec.LookPath("httpx"); err != nil {
		fmt.Println("[!] httpx não encontrado — probe HTTP pulado.")
		return
	}

	jsonlPath := filepath.Join(httpDir, "httpx.jsonl")
	outFile, err := os.Create(jsonlPath)
	if err != nil {
		fmt.Printf("[-] Erro ao criar %s: %v\n", jsonlPath, err)
		return
	}
	defer outFile.Close()

	// -json dá saída estruturada (sem parsing frágil de texto).
	// Campos extras (title/server/tech/cl/location) saem numa requisição só.
	cmd := exec.CommandContext(ctx, "httpx",
		"-l", inputFile,
		"-silent",
		"-json",
		"-sc",       // status-code
		"-title",    // title
		"-server",   // webserver
		"-td",       // tech-detect (substitui o webanalyze na maioria dos casos)
		"-cl",       // content-length
		"-location", // redirect location
		"-timeout", "8",
	)
	cmd.Stdout = outFile
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.Canceled {
			fmt.Println("\n[!] httpx cancelado (CTRL + C). Avançando...")
			return
		}
		fmt.Printf("[-] Erro no httpx: %v\n", err)
		// não retorna: pode ter saída parcial válida para parsear
	}
	outFile.Sync()

	// Deriva os arquivos de trabalho a partir do JSONL:
	//   status200.txt  -> URLs com status "vivo" (alimenta crawl/JS)
	//   http/live.txt  -> mesma coisa, nome mais claro (compatibilidade futura)
	vivos, status200 := derivarVivos(jsonlPath)

	if err := escreverLinhas(filepath.Join(resultadosDir, "status200.txt"), status200); err != nil {
		fmt.Printf("[-] Erro ao gravar status200.txt: %v\n", err)
	}
	if err := escreverLinhas(filepath.Join(httpDir, "live.txt"), vivos); err != nil {
		fmt.Printf("[-] Erro ao gravar http/live.txt: %v\n", err)
	}

	fmt.Printf("[+] httpx: %d host(s) vivo(s) (http/httpx.jsonl), %d com 2xx em status200.txt.\n",
		len(vivos), len(status200))
}

// derivarVivos lê o JSONL do httpx e devolve:
//
//	vivos     -> URLs com status em statusVivos (200/201/204/301/302/401/403/405)
//	status200 -> URLs estritamente 2xx (200/201/204), para o crawl/JS que
//	             só faz sentido sobre conteúdo servido de fato.
func derivarVivos(jsonlPath string) (vivos, status200 []string) {
	f, err := os.Open(jsonlPath)
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		linha := strings.TrimSpace(sc.Text())
		if linha == "" {
			continue
		}
		var h linhaHttpx
		if err := json.Unmarshal([]byte(linha), &h); err != nil || h.URL == "" {
			continue
		}
		if !statusVivos[h.StatusCode] {
			continue
		}
		vivos = append(vivos, h.URL)
		if h.StatusCode >= 200 && h.StatusCode < 300 {
			status200 = append(status200, h.URL)
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Printf("[-] Erro lendo %s: %v\n", jsonlPath, err)
	}
	return vivos, status200
}

func escreverLinhas(caminho string, linhas []string) error {
	f, err := os.Create(caminho)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, l := range linhas {
		w.WriteString(l)
		w.WriteByte('\n')
	}
	return w.Flush()
}
