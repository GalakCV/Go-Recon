# go-recon

Pipeline de reconhecimento para bug bounty, escrito em Go. É a versão refatorada do antigo `teste.sh` (bash), reorganizada em módulos, com cancelamento gracioso via `CTRL+C` e execução sequencial e transparente das etapas.

## Visão geral

O programa recebe uma lista de alvos e o nome da empresa, cria um workspace local e roda uma sequência de ferramentas externas conhecidas do ecossistema de recon (subfinder, dnsx, httpx, katana, jshunter, trufflehog), salvando cada resultado intermediário em arquivo, de forma que a próxima etapa sempre lê a saída da anterior.

```
Uso: go run main.go <Alvos.txt> <Nome_da_Empresa>
```

Ao rodar, o programa cria a estrutura:

```
<Nome_da_Empresa>/
└── resultados/
```

Todos os arquivos gerados pelas etapas ficam dentro de `resultados/`.

## Pipeline

```
subdominios.txt (subfinder)
        ↓
resolvidos.txt (dnsx)
        ↓
statuscode-httpx.txt (httpx -sc)  → status200.txt
        ↓
js-candidates.txt (katana -jc, filtro/normalização/dedup)
        ↓
js-validos.txt (httpx -mc 200 -ct -fpt -fep -fd)
        ↓
jshunter.txt (jshunter -ep, saída bruta em texto)
        ↓
urls.txt (endpoints extraídos do jshunter.txt, sem filtro)
        ↓
javascripts/ (arquivos .js baixados, nomeados por SHA1 da URL)
        ↓
segredos-trufflehog.json (trufflehog filesystem sobre javascripts/)
```

## Estrutura do projeto

| Pacote | Arquivo | Responsabilidade |
|---|---|---|
| `main` | `main.go` | Orquestra as etapas em sequência, cria o ambiente de trabalho, trata `CTRL+C` por etapa |
| `rv1subdominios` | `rv1-subdominios/subdominiosv1.go` | `Subdominios` (subfinder) e `ResolucaoSubdominios` (dnsx) |
| `rv1recongeral` | `rv1-recongeral/recongeralv1.go` | `HttpxStatus`: valida status code e extrai os hosts com resposta `200` |
| `rv1js` | `rv1-js/reconjs.go` | `ColetarJS` (katana + normalização/dedup de URLs `.js`) e `ValidarJS` (confirma que o JS está ativo via httpx) |
| `rv1jsanalise` | `rv1-jsanalise/analisev1.go` | `ExtrairEndpoints` (jshunter), `BaixarJS` (download dos `.js`), `AnalisarSegredos` (trufflehog) |

### Etapas registradas em `main.go`

```go
etapas := []struct{ ... }{
    {"Subdomínios (Subfinder)",              rv1subdominios.Subdominios},
    {"Resolução de Subdomínios (Dnsx)",      rv1subdominios.ResolucaoSubdominios},
    {"Recon Geral Status (HttpxStatus)",     rv1recongeral.HttpxStatus},
    {"Coleta de JavaScript (Katana)",        rv1js.ColetarJS},
    {"Validação de JavaScript",              rv1js.ValidarJS},
    {"Extração de Endpoints (Jshunter)",     rv1jsanalise.ExtrairEndpoints},
    {"Download de JavaScript",               rv1jsanalise.BaixarJS},
    {"Busca de Segredos (Trufflehog)",       rv1jsanalise.AnalisarSegredos},
}
```

> A etapa `Httpx` original (recon geral completo, com `-td -title -server -tls-probe` + formatação via `jq`) foi **removida** para reduzir ruído/tráfego. Só sobrou a checagem de status code (`HttpxStatus`), que é a que alimenta o restante do pipeline.

## Arquivos gerados em `resultados/`

| Arquivo | Origem | Conteúdo |
|---|---|---|
| `subdominios.txt` | subfinder | Subdomínios descobertos |
| `resolvidos.txt` | dnsx | Subdomínios que resolvem DNS |
| `statuscode-httpx.txt` | httpx `-sc` | URL + status code |
| `status200.txt` | parser interno | Só as URLs com status `200` |
| `js-candidates.txt` | katana `-jc` + filtros | URLs `.js` normalizadas, deduplicadas, sem infra/challenge (Cloudflare, captcha etc.) |
| `js-validos.txt` | httpx (`-mc 200 -ct -fpt -fep -fd`) | JS confirmados como ativos e com Content-Type JavaScript |
| `jshunter.txt` | jshunter `-ep` | Saída bruta em texto (`URL:` / `ENDPOINT:`) |
| `urls.txt` | parser do `jshunter.txt` | Endpoints extraídos, sem filtro de escopo |
| `javascripts/*.js` | download direto | Corpo de cada JS de `js-validos.txt`, nome = SHA1 da URL |
| `segredos-trufflehog.json` | trufflehog `filesystem` | Segredos encontrados nos arquivos baixados |

## Requisitos externos

O programa não faz nada sozinho — ele orquestra binários que precisam estar no `PATH`:

- [`subfinder`](https://github.com/projectdiscovery/subfinder)
- [`dnsx`](https://github.com/projectdiscovery/dnsx)
- [`httpx`](https://github.com/projectdiscovery/httpx)
- [`katana`](https://github.com/projectdiscovery/katana)
- [`jshunter`](https://github.com/cc1a2b/jshunter)
- [`trufflehog`](https://github.com/trufflesecurity/trufflehog)

Go `1.27+` para compilar (`go.mod` declara `go 1.27.0`).

> `jq` **não é mais necessário** — era usado só na etapa `Httpx` completa, que foi removida.

## Comportamento de cancelamento (`CTRL+C`)

Cada etapa roda com seu próprio `context.Context`. Pressionar `CTRL+C` cancela **apenas a etapa atual** (via `exec.CommandContext` ou checagem manual de `ctx.Done()` nos módulos que usam `net/http` direto, como `BaixarJS`) e o pipeline segue para a próxima, em vez de matar o programa inteiro.

## Limitações conhecidas

- **Sem filtro de escopo** na descoberta de subdomínios (só `subfinder`, sem `crt.sh`/`assetfinder` nem normalização de `targets.txt` como no `teste.sh` original).
- **Sem timeout automático por ferramenta** — só cancelamento manual via `CTRL+C`; se um binário travar, não há saída automática.
- **Sem execução paralela** entre alvos/arquivos (o `teste.sh` usava `xargs -P` para o download+análise de JS; aqui é sequencial).
- **Sem log persistente em arquivo** — toda saída vai para stdout/stderr.
- `HttpxStatus` identifica linhas com status `200` via `strings.Contains(line, "200")`, o que pode gerar falso positivo em casos como porta `8200` no meio da URL. Pendente de correção (idealmente checar o padrão `[200]` isolado).
- `urls.txt` (saída do `jshunter`) ainda **não tem filtro de escopo** — pode conter endpoints de terceiros (CDNs, APIs de terceiros como Google/OAuth) que apareceram embutidos em JS de terceiro.

## Roadmap / próximos passos

Itens já definidos, ainda não implementados:

1. **Merge de URLs históricas**: rodar `gau` + `waybackurls` e juntar o resultado em `urls.txt`, ao lado do que já é extraído pelo `jshunter`.
2. **Filtro de escopo antes de validar**: antes de qualquer chamada de rede de validação, descartar URLs cujo host não pertence ao domínio do alvo (evita tráfego/ruído desnecessário contra terceiros).
3. **Validação ampliada de endpoints**: rodar `httpx` sobre `urls.txt` (já filtrado por escopo) aceitando os status `200,201,204,301,302,401,403,405` — diferente da validação de JS, aqui `401/403/405` também contam como "endpoint existe", não só `200`.
4. **`url-validadas.txt`**: saída final desse processo de validação, já filtrada por escopo e com status relevante.
5. **Script `.sh` externo**: separado do binário Go, responsável por normalizar e filtrar tudo que sai de `resultados/` antes de inserir no banco de dados (a ideia é manter o Go focado em coleta bruta, e o `.sh` cuidar da limpeza final para consumo pelo banco/HTML).

## Ordem final planejada (com os itens do roadmap)

```
... (pipeline atual) ...
        ↓
urls.txt = jshunter + gau + waybackurls (merge)
        ↓
filtro de escopo
        ↓
validação (httpx, status 200/201/204/301/302/401/403/405)
        ↓
url-validadas.txt
        ↓
(fora do binário Go) script .sh de normalização → banco de dados
```
