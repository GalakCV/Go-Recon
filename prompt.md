# Prompt de Melhorias — GoRecon (pacote Go em /home/kali/gorecon/)

## Contexto

Você é um engenheiro de segurança especializado em pipelines de bug bounty. Vamos refatorar o **GoRecon**, um pipeline de recon escrito em Go (`/home/kali/gorecon/`), que hoje orquestra ferramentas externas (subfinder, dnsx, httpx, katana, jshunter, trufflehog, uro, gf) e alimenta um dashboard web (`http://127.0.0.1:8888`) com os resultados.

Estado atual do pipeline Go (módulos `rv1-*`):

- `rv1-subdominios` → subfinder + dnsx
- `rv1-recongeral` → httpx status code (extrai `status200.txt`)
- `rv1-js` → katana para coletar `.js` (normalização + filtro de infra/challenge) e `ValidarJS` (httpx)
- `rv1-js-analise` → jshunter para extrair endpoints, download dos `.js`, trufflehog para segredos
- `rv1-crawling` → crawling/organização de URLs
- `rv1-validacao` → Uro (dedup) + gf (separação por vetor: xss, sqli, lfi, ssrf, idor, redirect, rce, ssti, lfi-os, cors)
- `rv1-admin` → scanner de painéis admin
- `rv1-disclosure` → scanner de Spring Boot Actuator + GraphQL (probe HTTP real)
- `rv1-cdn` → classificação de CDN por range de IP + CNAME
- `rv1-cloud` → análise de cloud
- `rv1-tecnologia` → fingerprint de tecnologias
- `recon-dash` → dashboard web
- `database_create` → popula o banco lido pelo dashboard

Além do pacote Go, existe um script Bash legado mais maduro: `teste.sh` (apelidado **Recon5**, 519 linhas), cujo módulo de JavaScript intelligence é claramente superior ao do pacote Go. O objetivo principal deste trabalho é **replicar e melhorar no pacote Go o pipeline de reconhecimento de JavaScript do `teste.sh`**, além de corrigir os problemas de qualidade apontados abaixo.

---

## Diagnóstico (resultado de uma análise real do dashboard)

Foram observados os seguintes problemas na saída atual (alvo: ecossistema .gov do State Department, com `.gov`, `.net` e `.com` no escopo — ex.: `state.gov`, `iawg.gov`, `ibwc.gov`, `rewardsforjustice.net`, `elguardia.net`, `ustraveldocs.com`, `usvisascheduling.com`):

### 1. Egress HTTP envenenando a validação (407 Proxy Authentication Required)
- Dos 830 hosts, apenas 260 têm `StatusCode` preenchido.
- Desses 260, **115 (44%) retornam `407`**, ou seja, o tráfego de validação está saindo por um proxy egress que exige autenticação. Esses hosts **nunca foram realmente alcançados** — a resposta não é do alvo.
- A cobertura real de validação cai para ~145 hosts, dos quais só ~21 retornaram `200`.

**Ação:** corrigir o egress (remover/não usar proxy para as sondas, ou permitir autenticação de proxy configurável via flag/env); implementar detecção explícita de `407`/`407 Proxy Authentication Required` como "host não validado" (não contar como resposta do alvo), com re-tentativa sem proxy e registro claro em log.

### 2. Classificação de vetores por heurística simples (muitos falsos positivos)
- Os vetores de ataque são gerados hoje por `rv1-validacao` usando `gf` (padrões regex) sobre as URLs. Isso é geração de **candidatos**, não confirmação de vulnerabilidade.
- Falsos positivos concretos observados:
  - **RCE** apontando para arquivos `.js` e URLs `api/v1?command=` (parâmetro apenas sugestivo, sem comprovação).
  - **SSRF** apontando para downloads de arquivos estáticos (ex.: `rawmedia_repository/...?filename=x.pdf`).
  - **IDOR** incluindo URLs de authorize OAuth (Okta) e links de PDF.
  - **SQLI** em `.asp?menu_id=` e `content_id=` (heurística clássica de parâmetro numérico, sem confirmação).
- Os rótulos inflam a severidade e geram ruído alto.

**Ação:** manter o `gf` apenas como *seed/coleta de candidatos*, e adicionar uma **nova etapa de confirmação** (ver abaixo em "Confirmação de vetores").

### 3. Deduplicação/normalização fraca
- `http://`, `https://` e sufixo `:80` estão sendo tratados como domínios distintos (ex.: `iawg.gov`, `iawg.gov:80`, `www.iawg.gov:80`).
- Isso infla o total de vetores (9611) com duplicatas.

**Ação:** normalizar canonicamente cada URL (esquema → https quando aplicável, remover porta default 80/443, minúsculas em host, remover fragmento) e deduplicar por chave canônica **após** a classificação, preservando a origem (arquivo/detecção) como metadado.

### 4. Reconhecimento de JS inferior ao `teste.sh`
O módulo de JS do pacote Go (`rv1-js` + `rv1-js-analise`) hoje:
- Coleciona `.js` via katana, valida via httpx e extrai endpoints **apenas com jshunter** (regex/linha `ENDPOINT:`).
- **Não prioriza** os arquivos antes de baixar (baixa tudo, inclusive vendor/CDN/analytics).
- **Não** lida com concatenação de strings/variáveis em JS.
- **Não** combina múltiplos extratores.
- **Não** separa descoberta atual (crawl) de histórica (arquivo).
- **Não** faz validação HTTP direcionada dos endpoints extraídos.

O `teste.sh` (Recon5) já resolve boa parte disso. Reproduza e aprimore esse comportamento em Go.

---

## Objetivo 1 — Replicar/melhorar o reconhecimento de JavaScript do `teste.sh` no pacote Go

O `teste.sh` implementa um módulo de JavaScript intelligence em 4 fases. Reimplemente tudo isso no pacote Go (`rv1-js` e `rv1-js-analise`), com as melhorias indicadas:

### Fase A — Priorização ANTES do download (js-priority)
- Classificar cada candidato `.js` em tiers: **HIGH / MEDIUM / LOW / SKIP**.
- **SKIP** é para terceiros (analytics, CDN, vendor, captcha, consent, etc.) — registrar em `js/third_party.txt` e **nunca baixar**.
- Critérios de score: domínio in-scope, presença de palavras-chave de alto valor no path/nome (`app`, `main`, `config`, `api`, `auth`, `endpoint`, `route`, `admin`, `chunk`, `bundle` próprio, `webpack`, `vite`, etc.), proximidade do domínio raiz, fonte (crawl tem prioridade sobre histórico).
- Expor cutoff configurável por flag/env (ex.: `JS_DOWNLOAD_TIER`, default `LOW`).

### Fase B — Download seletivo
- Baixar apenas os candidatos acima do cutoff.
- Usar worker pool com **concorrência configurável** (hoje o Go baixa sequencial; o `teste.sh` usa `xargs -P`).
- Timeout por download, limite de tamanho (`MaxBytesReader`), hash SHA1 do conteúdo como nome de arquivo (comportamento atual ok, manter + melhorar com retry e validação de Content-Type).

### Fase C — Extração de conteúdo (multi-extrator)
Implementar **três extratores** que alimentam um único pipeline de resolução:

1. **Extrator próprio (regex + urljoin + concatenação de variáveis):**
   - Regex para URLs literais, paths e endpoints.
   - Heurística de **concatenação de variáveis**: detectar padrões como `BASE + "/x"`, `base + "/x"`, `${BASE}/x`, template literals `` `${base}/x` ``, e resolver contra strings/constantes declaradas no mesmo arquivo.
   - Resolver caminhos relativos contra a URL de origem (urljoin).
   - Aplicar filtro de escopo antes de persistir.

2. **LinkFinder** (opcional, se disponível em `PATH` ou via caminho configurável): extração baseada em regex mais agressiva.

3. **jsluice** (opcional, fortemente recomendado): extrator **baseado em AST** (`github.com/BishopFox/jsluice`), que resolve concatenação e ofuscação nativamente. Extrair `.url` de `jsluice urls --json`.

- Cada endpoint extraído deve carregar proveniência (`tool`, `source`) em `js/sources.jsonl` (uma linha JSON por endpoint, com campost `endpoint`, `source`, `tool`, `scope`, `tier`, `resolved`).
- Arquivos grandes de tier LOW podem pular os extratores mais lentos (LinkFinder/jsluice) para respeitar o orçamento de tempo — manter esse comportamento do `teste.sh`.

### Fase D — Agregação + segredos
- Agregar `js/sources.jsonl` em: `js/endpoints.txt`, `js/endpoints_full.txt` (com contexto de origem), `js/domains.txt`, merge em `api/endpoints.txt`, `api/graphql.txt`, `js/js_parameters.txt`.
- **Separação de fonte**: marcar endpoints descobertos por **crawl atual** (katana) vs **histórico** (gau/wayback/waymore). Histórico é mantido (endpoints antigos podem seguir vivos), mas depriorizado.
- Scan de segredos com trufflehog (manter) e adicionar `gitleaks` + regexes próprias como fallback, consolidando em `js/secrets.txt`.

### Fase E — Validação HTTP direcionada
- Após a extração, validar **apenas** `api/endpoints.txt` + `api/graphql.txt` (nunca o corpus inteiro de URLs), aceitando status `200,201,204,301,302,401,403,405` como "endpoint existe".
- Gerar `api/endpoints_probed.txt` com status/size/tecnologia.

### Melhorias adicionais sobre o `teste.sh` (o que ele ainda não faz e deve ser feito agora no Go)
- **Filtro de escopo em todos os estágios** (ele já tem gaps — reforçar).
- `gau` + `waybackurls` + `waymore` para merge histórico, com tag de origem e dedup canônica.
- Preservar o conceito de "candidato JS" em um único arquivo rastreável (`js/candidates.tsv`) com colunas: `url`, `source` (crawl/historical), `tier`.

## Objetivo 2 — Corrigir as heurísticas de RCE/SSRF/SQLi/IDOR/etc. (menos falsos positivos)

O `rv1-validacao` deve deixar de ser a etapa final de classificação. Ajuste assim:

1. **Renomear semanticamente:** a saída do `gf` passa a ser `vetores_ataque/*.candidatos.txt` (candidatos), não "vulnerabilidades".
2. **Separar a etapa de confirmação real**, adicionando um novo módulo (`rv1-confirmacao` ou evoluindo `rv1-disclosure`):

### Confirmação por vetor (feita com ferramentas externas usadas pelos hunters)

- **XSS / Reflexão:** usar `dalfox` (github.com/hahwul/dalfox) e/ou `kxss` (github.com/Emoe/kxss) para confirmar reflexão; registrar parâmetro, payload e evidência de reflexão no resultado.
- **SQLi:** confirmar com `sqlmap` (modo `--batch --level=1 --risk=1` apenas em candidatos) ou `ghauri`; **somente em endpoints autorizados/in-scope**, nunca automatizado contra produção de terceiros.
- **Open Redirect:** verificar com payload canônico (`//evil.com`, `https://evil.com`) e comparar `Location`/destino final.
- **SSRF:** testar parâmetro com colaborador (Burp Collaborator/Interactsh via `nuclei` ou `interactsh-client`); só marcar como SSRF quando houver callback comprovado.
- **RCE / SSTI / LFI:** usar **nuclei** com templates específicos (ex.: `nuclei -tags rce,ssti,lfi`) — github.com/projectdiscovery/nuclei + núcleo de templates (nuclei-templates). Tratar como "suspeito" até haver evidência (ex.: echo de cálculo em SSTI, vazamento de arquivo em LFI).
- **Actuator / GraphQL:** manter os scanners existentes (`rv1-disclosure`), que já fazem probe HTTP real — apenas melhorar `GraphQL` para fazer requisição GET além de POST e detectar HTML de playground (GraphiQL/GraphQL Playground).

3. **Modelo de severidade em 3 níveis** para cada vetor: `CONFIRMADO` (evidência objetiva), `SUSPEITO` (comportamento anômalo) e `CANDIDATO` (apenas assinatura). O dashboard deve exibir essa coluna e deixar filtrar por `CONFIRMADO` primeiro.

4. **Deduplicar e normalizar** antes de persistir (ver item 3 do diagnóstico).

## Objetivo 3 — Correções gerais e hardening

1. **Egress/proxy:** flag `-proxy` e env `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` respeitados por todos os clientes `net/http`; detecção de `407` com re-tentativa direta; nunca contar `407` como resposta do alvo.
2. **Timeout por ferramenta externa:** todo `exec.CommandContext` deve ter `context.WithTimeout` com valor default configurável (não depender só de CTRL+C).
3. **Execução paralela:** worker pools (semaforo) em subfinder/katana/downloads/validação, com limite configurável (`MAX_PROCS`).
4. **Log persistente:** escrever em `<empresa>/resultados/recon.log` (além de stdout), com timestamp.
5. **Corrigir `HttpxStatus`:** hoje usa `strings.Contains(line, "200")` — trocar por parse correto do campo de status (ex.: `[200]`) ou usar saída JSON do httpx (`-json`) para evitar falso positivo em porta `8200`.
6. **Validação ampliada:** após extrair endpoints, rodar httpx aceitando `200,201,204,301,302,401,403,405` e gerar `url-validadas.txt`.
7. **Escopo:** centralizar a lógica de "is in scope" em uma única função usada por todos os módulos, suportando wildcard de subdomínio (`*.dominio`) e lista explícita de hosts.

---

## Ferramentas externas recomendadas (GitHub, já usadas pela comunidade de hunters)

Para não reinventar a roda, use (detectando presença em `PATH` e degradando graciosamente se ausente):

**Descoberta de URL/JS:**
- `katana` (projectdiscovery) — manter como crawl primário
- `gau` (lc/gau) — URLs históricas (AlienVault/CommonCrawl)
- `waybackurls` (tomnomnom) — Wayback Machine
- `waymore` (xnl-h4ck3r) — mais arquivos históricos/wayback
- `subjs` (lc/subjs) — descoberta de JS via JS/HTML sources
- `getJS` (003random/getJS) — descoberta de JS

**Extração de endpoints/segredos em JS:**
- `jsluice` (BishopFox) — AST, resolve concatenação/ofuscação — **preferencial**
- `linkfinder` (GerbenJavado) — regex agressiva
- `jshunter` (cc1a2b) — manter como um dos extratores
- `secretfinder` (m4ll0k) — regex de segredos
- `trufflehog` (trufflesecurity) e `gitleaks` (gitleaks) — scan de segredos

**Confirmação de vulnerabilidades:**
- `nuclei` (projectdiscovery) + nuclei-templates — RCE/SSTI/LFI/exposures/misconfig
- `dalfox` (hahwul) — XSS
- `kxss` (Emoe) — triagem de parâmetros refletidos
- `sqlmap` (sqlmapproject) — SQLi
- `ghauri` (r0oth3x49) — SQLi (alternativa moderna)
- `interactsh-client` (projectdiscovery) — OOB para SSRF
- `ffuf` / `feroxbuster` — caso precise de fuzzing de paths

**Superfície além do JS / exposições de arquivos:**
- `git-dumper` (arthaud/git-dumper) — dump de `.git/` exposto
- `nuclei` templates de `exposures/configs` — `.env`, `web.config`, `server-status`, `.DS_Store`, `.git/config`, sourcemaps

**Takeover / DNS de alto valor:**
- `subzy` (LukaSikic/subzy) ou `can-i-take-over-xyz` (EdOverflow) — detecção + validação de subdomain takeover
- `dnsx` (já usado) — adicionar checagens de CAA/DMARC e sinalização de CNAME "dangling"

**Triagem visual e evidência:**
- `gowitness` (sensepost/gowitness) ou `aquatone` (michenriksen/aquatone) — screenshots para revisão rápida de painéis/login
- `wafw00f` (EnableSecurity/wafw00f) — detecção de WAF para ajustar payloads
- `kiterunner` (assetnote/kiterunner) — enumeração de rotas de API (swagger/OpenAPI/wordlist)
- `qsreplace` (tomnomnom) — injeção de canário para confirmação de reflexão

Requisitos de integração: toda ferramenta externa deve ser opcional (detecção em `PATH`), ter timeout, cancelamento por contexto, e sua ausência deve ser reportada no final (como o `teste.sh` faz com `MISSING_TOOLS`).

---

## Sugestões adicionais (visão AppSec / Bug Hunter)

Além dos objetivos acima, como analista de AppSec eu adicionaria:

### A. Ampliar a superfície além do JavaScript
Os segredos/endpoints de maior valor frequentemente estão fora de `.js`:
- **Sourcemaps (`.js.map`)**: baixar e minerar — revelam código-fonte original (strings, rotas e segredos removidos na minificação). Mapear referências `//# sourceMappingURL=` em cada JS baixado.
- **Scripts inline**: extrair blocos `<script>...</script>` inline das respostas (katana sozinho não pega) e aplicar o mesmo pipeline de extração.
- **Arquivos de descoberta/config**: `robots.txt`, `sitemap.xml`, `/.well-known/security.txt`, `crossdomain.xml`, `humans.txt` e manifestos web (`manifest.json`).
- **Exposições de código/config**: `.git/`, `.svn/`, `.env`, `web.config`, `server-status`, `trace.axd`, `elmah.axd`, `.DS_Store` e backups (`backup.zip`, `*.bak`).

### B. Auto-descrição de APIs (altíssimo valor, pouco esforço)
- Probar fingerprints de **OpenAPI/Swagger** (`/swagger.json`, `/v2/api-docs`, `/openapi.json`, `/swagger-ui.html`), **GraphiQL/Playground** (`/graphiql`, `/playground`) e **gRPC reflection** — por host in-scope. Um único `swagger.json` aberto vale mais que 100 endpoints adivinhados.
- Para GraphQL, além da introspecção: testar `query depth/alias` (DoS) e mutations sem autenticação.

### C. Subdomain takeover (bounty de baixo risco, alto retorno)
- Detectar CNAME "dangling" (aponta para serviço inexistente: S3, GitHub Pages, Heroku, Azure, etc.) e validar a possibilidade de assunção de controle. O `rv1-cdn` já resolve CNAME — evolua para sinalizar candidatos a takeover, e confirme com `subzy`/`can-i-take-over-xyz` ou `nuclei -tags takeover`.

### D. Triagem visual e evidência reprodutível
- **Screenshots automatizados** (gowitness/aquatone) de todos os hosts vivos: acelera muito a revisão de painéis admin, logins e páginas "interessantes" que status-code sozinho não revela.
- Para cada vetor `CONFIRMADO`, **armazenar evidência reprodutível** (raw request/response + curl + screenshot do DOM). Bounty sem evidência reprodutível é report rejeitado.

### E. Detecção de WAF e ajuste de payload
- Detectar WAF (Cloudflare, AWS WAF, Imperva) por host e registrar no dashboard — o `rv1-cdn` classifica rede, mas não a camada de WAF de aplicação. Ajustar o orçamento/agressividade dos payloads conforme o WAF presente.

### F. Resiliência operacional (essencial para alvos .gov)
- **Checkpoint/resume por etapa**: poder retomar de qualquer estágio sem reprocessar tudo (alvos .gov são grandes; refazer subfinder+httpx a cada ajuste é caro).
- **Diff temporal entre execuções**: guardar o estado anterior (hash) e destacar o que mudou (novos hosts, endpoints removidos, tecnologias novas) — isso transforma recon em monitoramento contínuo.
- **Rate-limit + User-Agent identificável**: limitar requests/s, definir User-Agent customizado (ex.: `GoRecon/<versao> (security research)`), respeitar `robots.txt` quando aplicável e manter um registro de auditoria do que foi acessado.

### G. Ética/legal em alvos .gov
- Nunca automatizar exploits destrutivos (RCE/SQLi intrusivo) sem autorização explícita do programa. Preferir **validação passiva/baixo impacto** (assinatura de resposta, reflection, introspecção, erro controlado) e deixar o impacto real para uma prova de conceito mínima, controlada e documentada.
- Manter o filtro de escopo **obrigatório por padrão**, desativável somente com `--allow-out-of-scope` explícito + warning.

---

## Critérios de aceite

1. O pacote Go reproduz **todas** as fases do recon JS do `teste.sh` (priorização → download seletivo → extração multi-ferramenta com concatenação de variáveis → agregação → segredos → validação direcionada).
2. Vetores de ataque são separados em `CANDIDATO`, `SUSPEITO` e `CONFIRMADO`, com o dashboard exibindo e filtrando por esse campo.
3. Falsos positivos óbvios (RCE em `.js`, SSRF em download de PDF, IDOR em authorize OAuth) deixam de ser classificados como vulnerabilidade confirmada.
4. `407` não conta mais como resposta válida do alvo; há re-tentativa sem proxy e log claro.
5. URLs são deduplicadas por chave canônica (esquema/porta/host normalizados).
6. Todas as ferramentas externas são opcionais, com timeout e cancelamento gracioso.
7. Saídas continuam alimentando o dashboard existente sem quebra de schema (ou com migração documentada).
8. Sourcemaps e scripts inline são minerados, e fingerprints de OpenAPI/Swagger/GraphiQL/gRPC passam a alimentar o relatório de exposição.
9. Detecção de WAF e candidatos a subdomain takeover são registrados e exibidos no dashboard.
10. Há checkpoint/resume por etapa e diff temporal entre execuções.
11. Evidência reprodutível (raw request/response + curl + screenshot) é anexada a todo vetor `CONFIRMADO`.
