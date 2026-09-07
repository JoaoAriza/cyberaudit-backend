<#
.SYNOPSIS
    Restaura um dump do Postgres numa instância NOVA (Render pago).

.DESCRIPTION
    Par do dump-postgres.ps1. Serve para o momento da migração: o banco gratuito
    expira, você cria o pago, e os dados precisam atravessar.

    NÃO usa --clean nem --if-exists de propósito. Essas opções derrubam os
    objetos antes de recriar, e um erro de digitação na URL apontando para o
    banco errado apagaria o banco errado. Restaure sempre numa instância vazia;
    se ela não estiver vazia, pare e entenda por quê antes de forçar.

.EXAMPLE
    .\deploy\restore-postgres.ps1 -Arquivo "$env:USERPROFILE\backups-cyberaudit\cyberaudit-2026-09-06-2340.dump"
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Arquivo,

    # Mesma regra do dump: a ferramenta precisa ser igual ou mais nova que o
    # servidor. A Render rodava 18.4 em 2026-09-06. Se o destino for mais novo,
    # passe -Imagem postgres:<versao>.
    [string]$Imagem = "postgres:18"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Arquivo)) { throw "Arquivo nao encontrado: $Arquivo" }

& docker info *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Docker nao esta respondendo. Abra o Docker Desktop, espere ficar verde, e rode de novo."
}

$pasta = Split-Path -Parent  $Arquivo
$nome  = Split-Path -Leaf    $Arquivo

Write-Host ""
Write-Host "=== Restore do Postgres ===" -ForegroundColor Cyan
Write-Host "Arquivo: $Arquivo"
Write-Host ""
Write-Host "Pegue a URL da instancia NOVA no painel da Render:" -ForegroundColor Yellow
Write-Host "  o novo banco -> Connect -> External Database URL"
Write-Host ""
Write-Warning "Isto ESCREVE no banco de destino. Confira que a URL e a da instancia nova."
Write-Host ""

$segura = Read-Host "Cole a External Database URL do banco NOVO" -AsSecureString
$url    = [System.Net.NetworkCredential]::new("", $segura).Password

if ([string]::IsNullOrWhiteSpace($url)) { throw "URL vazia." }
if (-not $url.StartsWith("postgres")) {
    throw "A URL deve comecar com postgresql:// — voce colou a JDBC ou a Internal?"
}
if ($url -notmatch "sslmode=") {
    $url += $(if ($url -match "\?") { "&" } else { "?" }) + "sslmode=require"
}

# Última chance de parar antes de escrever.
$ok = Read-Host "Digite RESTAURAR para confirmar"
if ($ok -ne "RESTAURAR") { Write-Host "Cancelado." -ForegroundColor Yellow; exit 0 }

# --no-owner e --no-privileges pelo mesmo motivo do dump: o dono dos objetos na
# instancia nova e outro role, e insistir no antigo faz o restore falhar.
$cmd = 'pg_restore --dbname="$PGURL" --no-owner --no-privileges --verbose /dump/' + $nome

docker run --rm `
    -v "${pasta}:/dump" `
    -e PGURL="$url" `
    $Imagem `
    sh -c $cmd

# pg_restore devolve codigo != 0 tambem por avisos que nao impedem o resultado
# (extensao ja existente, por exemplo). Por isso a conferencia abaixo e o que
# decide, nao o codigo de saida.
if ($LASTEXITCODE -ne 0) {
    Write-Warning "pg_restore terminou com codigo $LASTEXITCODE. Pode ser apenas aviso — confira a contagem abaixo."
}

Write-Host ""
Write-Host "Conferindo o que chegou no destino..." -ForegroundColor Cyan

$sql = @"
SELECT 'app_user' t, count(*) n FROM app_user
UNION ALL SELECT 'accounts',     count(*) FROM accounts
UNION ALL SELECT 'scan_records', count(*) FROM scan_records
UNION ALL SELECT 'domains',      count(*) FROM domains;
"@ -replace "`r?`n", " "

docker run --rm -e PGURL="$url" $Imagem `
    sh -c ('psql --dbname="$PGURL" -c "' + $sql + '"')

Write-Host ""
Write-Host "Compare os numeros acima com o banco antigo antes de desligar ele." -ForegroundColor Yellow
Write-Host ""
