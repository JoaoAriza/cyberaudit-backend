<#
.SYNOPSIS
    Dump do Postgres de produção (Render), via Docker.

.DESCRIPTION
    O plano gratuito do Postgres da Render é APAGADO 30 dias após a criação. Este
    script existe para que essa data deixe de ser um risco: um dump custa alguns
    minutos e devolve contas, domínios verificados e todo o histórico de scans.

    Usa Docker em vez de um pg_dump instalado porque:

      1. não há pg_dump no PATH desta máquina;
      2. pg_dump se recusa a ler um servidor MAIS NOVO que ele. Fixando a imagem
         numa versão recente, o dump funciona com qualquer servidor igual ou mais
         antigo — e some a classe de erro mais comum nesse tipo de tarefa.

    A URL é pedida na execução, como texto protegido: não fica no histórico do
    PowerShell, não entra em arquivo e não passa por lugar nenhum além da memória
    do processo e da variável de ambiente do contêiner, que morre junto com ele.

.NOTES
    O arquivo gerado contém DADOS PESSOAIS (e-mails, hashes de senha, histórico).
    Por padrão ele é gravado FORA do repositório, e não deve ser commitado nem
    enviado para nuvem sem criptografia. LGPD vale para backup também.
#>

param(
    # Fora do repositório de propósito — ver .NOTES.
    [string]$Destino = "$env:USERPROFILE\backups-cyberaudit",

    # pg_dump lê servidores da própria versão ou MAIS ANTIGOS — nunca mais novos.
    #
    # Em 2026-09-06 a Render rodava Postgres 18.4. A primeira versão deste script
    # chutou 17 e falhou com "aborting because of server version mismatch". Por
    # isso o valor abaixo é só o ponto de partida: se o servidor for mais novo, o
    # script lê a versão da própria mensagem de erro e repete com a imagem certa.
    [string]$Imagem = "postgres:18"
)

$ErrorActionPreference = "Stop"

# O CLI do Docker estar instalado nao significa que o daemon esteja de pe. Sem
# esta checagem, a falha aparece como um erro de npipe no meio do script, que nao
# diz o que fazer a respeito.
& docker info *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Docker nao esta respondendo. Abra o Docker Desktop, espere ficar verde, e rode de novo."
}

Write-Host ""
Write-Host "=== Dump do Postgres de producao ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Pegue a URL no painel da Render:" -ForegroundColor Yellow
Write-Host "  cyberaudit-db -> Connect -> External Database URL"
Write-Host "  (comeca com postgresql://  -- a Internal NAO funciona daqui)"
Write-Host ""

$segura = Read-Host "Cole a External Database URL" -AsSecureString
$url    = [System.Net.NetworkCredential]::new("", $segura).Password

if ([string]::IsNullOrWhiteSpace($url)) { throw "URL vazia." }
if (-not $url.StartsWith("postgres")) {
    throw "A URL deve comecar com postgresql:// — voce colou a JDBC ou a Internal?"
}

# sslmode=require: a Render recusa conexao externa sem TLS, e o erro que ela
# devolve nao diz isso com clareza.
if ($url -notmatch "sslmode=") {
    $url += $(if ($url -match "\?") { "&" } else { "?" }) + "sslmode=require"
}

New-Item -ItemType Directory -Force -Path $Destino | Out-Null
$carimbo = Get-Date -Format "yyyy-MM-dd-HHmm"
$arquivo = "cyberaudit-$carimbo.dump"

Write-Host ""
Write-Host "Destino: $Destino\$arquivo" -ForegroundColor Cyan
Write-Host "Baixando/usando a imagem $Imagem..." -ForegroundColor DarkGray

# --no-owner e --no-privileges: o dump vai ser restaurado numa instancia NOVA,
# com outro usuario dono. Sem isso, o restore tenta atribuir objetos a um role
# que nao existe la e falha na primeira tabela.
#
# O comando e montado numa variavel, e nao interpolado na linha do docker, porque
# concatenar string literal com variavel em modo de argumento do PowerShell tem
# resultado ambiguo. Aspas simples aqui sao de proposito: $PGURL deve chegar
# literal e ser expandido pelo shell DE DENTRO do contêiner.
$cmdDump = 'pg_dump --dbname="$PGURL" --format=custom --no-owner --no-privileges --verbose --file=/dump/' + $arquivo

# Executa um comando nativo capturando stdout E stderr juntos, sem que o stderr
# vire exceção.
#
# O PowerShell 5.1 embrulha CADA LINHA de stderr de um .exe num ErrorRecord. Com
# ErrorActionPreference=Stop, a primeira delas encerra o script — e stderr aqui é
# saída ROTINEIRA: o "Unable to find image ... locally" que o docker imprime
# antes de baixar, e o --verbose do pg_dump, que reporta progresso por ali.
# Sem esta função, o script morria justamente quando estava funcionando.
# NÃO renomeie $Argumentos para $Args: $Args é variável AUTOMÁTICA do PowerShell
# (os argumentos não declarados da função). Um parâmetro com esse nome não recebe
# nada, o @Args expande a automática vazia, e o docker roda sem subcomando —
# imprimindo o próprio help como se fosse erro. Foi o que aconteceu aqui.
function Invoke-Nativo {
    param([string[]]$Argumentos)

    $anterior = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $saida  = & docker @Argumentos 2>&1
        $codigo = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $anterior
    }

    # .ToString() porque as linhas de stderr chegam como ErrorRecord, e imprimir
    # o objeto cru mostra "System.Management.Automation.RemoteException" no lugar
    # da mensagem.
    $saida | ForEach-Object { Write-Host $_.ToString() }
    return @{ codigo = $codigo; texto = (($saida | ForEach-Object { $_.ToString() }) -join "`n") }
}

function Invoke-Dump {
    param([string]$img)
    return Invoke-Nativo @(
        "run", "--rm",
        "-v", "${Destino}:/dump",
        "-e", "PGURL=$url",
        $img,
        "sh", "-c", $cmdDump
    )
}

$r = Invoke-Dump -img $Imagem

# "server version: 18.4 ... pg_dump version: 17.11" — a propria mensagem de erro
# carrega o numero de que precisamos. Repetir com a imagem correta e mais util
# que mandar a pessoa editar o script e rodar de novo.
if ($r.codigo -ne 0 -and $r.texto -match 'server version:\s*(\d+)') {
    $maior = $Matches[1]
    Write-Host ""
    Write-Warning "O servidor e Postgres $maior, e a imagem usada foi $Imagem. Repetindo com postgres:$maior..."
    Write-Host ""
    $Imagem = "postgres:$maior"
    $r = Invoke-Dump -img $Imagem
}

if ($r.codigo -ne 0) { throw "pg_dump falhou (codigo $($r.codigo)). Veja a saida acima." }

$completo = Join-Path $Destino $arquivo

# Codigo de saida 0 nao garante arquivo: se o docker for invocado errado ele
# imprime o proprio help e sai com 0, e o script seguiria adiante achando que
# deu certo. O arquivo existir e a unica prova que vale.
if (-not (Test-Path $completo)) {
    throw "pg_dump terminou sem erro mas NAO gerou '$completo'. Leia a saida acima — provavelmente o comando docker nao chegou a rodar."
}

$tamanho = (Get-Item $completo).Length

Write-Host ""
Write-Host "Dump gravado: $completo" -ForegroundColor Green
Write-Host "Tamanho: $([math]::Round($tamanho/1KB,1)) KB"

if ($tamanho -lt 1024) {
    Write-Warning "Arquivo suspeito de tao pequeno. Confira o conteudo antes de confiar nele."
}

# Um dump que nao se consegue ler nao e backup — e um arquivo. pg_restore --list
# le o indice interno: se ele responde, o arquivo esta integro e restauravel.
Write-Host ""
Write-Host "Conferindo se o dump e legivel..." -ForegroundColor Cyan

$cmdLista = 'pg_restore --list /dump/' + $arquivo
$lista    = Invoke-Nativo @("run", "--rm", "-v", "${Destino}:/dump", $Imagem, "sh", "-c", $cmdLista)

if ($lista.codigo -ne 0) {
    throw "pg_restore nao conseguiu ler o dump. NAO confie neste arquivo."
}

$tabelas = $lista.texto -split "`r?`n"
$qtd = ($tabelas | Select-String "TABLE DATA").Count
Write-Host "OK — dump legivel, com $qtd tabelas de dados." -ForegroundColor Green
Write-Host ""
Write-Host "Tabelas encontradas:" -ForegroundColor DarkGray
$tabelas | Select-String "TABLE DATA" | ForEach-Object { "  " + ($_ -replace '.*TABLE DATA\s+\w+\s+', '') }
Write-Host ""
Write-Host "Para restaurar na instancia nova (quando ela existir):" -ForegroundColor Yellow
Write-Host ""
Write-Host "  .\deploy\restore-postgres.ps1 -Arquivo `"$completo`""
Write-Host ""
Write-Host "Guarde o arquivo fora desta maquina tambem — um backup que mora no" -ForegroundColor DarkGray
Write-Host "mesmo lugar que o original nao protege contra perder o lugar." -ForegroundColor DarkGray
Write-Host ""
