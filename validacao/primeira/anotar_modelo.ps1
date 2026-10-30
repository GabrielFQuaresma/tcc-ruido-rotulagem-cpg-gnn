<#
.SYNOPSIS
  Roda o segundo anotador (modelo) sobre os pacotes cegos, via `claude -p`.

.DESCRIPTION
  Nao usa a Messages API e nao precisa de ANTHROPIC_API_KEY: chama o CLI do
  Claude Code em modo headless, que consome a assinatura / creditos de uso extra
  ja existentes.

  Uma chamada por caso, em processo separado, sem historico compartilhado: os
  casos nao se contaminam. Cada repeticao e uma passada independente sobre todos
  os casos. (Arquivo em ASCII puro de proposito - ver nota no corpo.)

  Resumivel: se o JSON bruto de uma chamada ja existe em brutos/, ela e pulada.
  Apague o arquivo para refazer so aquela chamada.

  Roda no PowerShell do Windows (o CLI do Claude Code esta instalado la; o WSL
  nao tem node).

.EXAMPLE
  .\anotar_modelo.ps1 -Condicao cve_visivel -Repeticoes 3
  .\anotar_modelo.ps1 -Condicao cve_oculta  -Repeticoes 1
  .\anotar_modelo.ps1 -Condicao cve_visivel -Repeticoes 3 -Simular
#>
[CmdletBinding()]
param(
    [ValidateSet('cve_visivel', 'cve_oculta')]
    [string]$Condicao = 'cve_visivel',

    [int]$Repeticoes = 3,

    [string]$Modelo = 'claude-opus-5',

    # Diretorio deste script; os pacotes ficam em <Raiz>\pacotes\<Condicao>.
    # Vazio = resolve no corpo ($PSScriptRoot nao e confiavel em param() sob -File).
    [string]$Raiz = '',

    # Subconjunto de ids, para teste de fumaca. Vazio = todos.
    [int[]]$Casos = @(),

    # So lista o que seria feito e estima o custo, sem chamar o modelo.
    [switch]$Simular,

    # Segundos entre chamadas, para nao saturar.
    [double]$Pausa = 1.0
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($Raiz)) {
    $Raiz = Split-Path -Parent $MyInvocation.MyCommand.Definition
}
if ([string]::IsNullOrWhiteSpace($Raiz)) { $Raiz = (Get-Location).Path }

$pacotesDir = Join-Path $Raiz "pacotes\$Condicao"
$brutosDir  = Join-Path $Raiz "brutos\$Condicao"
$saidaDir   = Join-Path $Raiz 'saida'
$logPath    = Join-Path $saidaDir "log_anotacao_$Condicao.txt"

if (-not (Test-Path $pacotesDir)) {
    throw "Pacotes nao encontrados em $pacotesDir. Rode preparar_pacotes.py primeiro."
}
foreach ($d in @($brutosDir, $saidaDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
}

$pacotes = Get-ChildItem -Path $pacotesDir -Filter 'caso_*.md' | Sort-Object Name
if ($Casos.Count -gt 0) {
    $pacotes = $pacotes | Where-Object { $Casos -contains [int]($_.BaseName -replace '\D', '') }
    Write-Host "Filtro -Casos ativo: $($Casos -join ', ')" -ForegroundColor Yellow
}
if ($pacotes.Count -eq 0) { throw "Nenhum pacote em $pacotesDir." }

# Ferramentas bloqueadas: o anotador julga so o texto do pacote. Sem isto ele
# poderia sair lendo o CSV do humano no disco e a cegueira iria pro lixo.
$semFerramentas = 'Bash Read Write Edit MultiEdit Glob Grep WebFetch WebSearch Task NotebookEdit TodoWrite Artifact'

$totalChamadas = $pacotes.Count * $Repeticoes
$totalChars = ($pacotes | Measure-Object -Property Length -Sum).Sum * $Repeticoes

Write-Host ''
Write-Host "Condicao   : $Condicao"
Write-Host "Modelo     : $Modelo"
Write-Host "Casos      : $($pacotes.Count)   Repeticoes: $Repeticoes   Chamadas: $totalChamadas"
Write-Host ("Entrada    : ~{0:N1} MB de prompt no total (~{1:N0} mil tokens)" -f ($totalChars/1MB), ($totalChars/4/1000))
Write-Host "Brutos     : $brutosDir"
Write-Host ''

if ($Simular) {
    Write-Host 'Modo -Simular: nada foi chamado.' -ForegroundColor Yellow
    $jaTem = 0
    foreach ($p in $pacotes) {
        $id = [int]($p.BaseName -replace '\D', '')
        for ($r = 1; $r -le $Repeticoes; $r++) {
            if (Test-Path (Join-Path $brutosDir ("caso_{0:d2}_run{1}.json" -f $id, $r))) { $jaTem++ }
        }
    }
    Write-Host "Chamadas ja feitas (seriam puladas): $jaTem de $totalChamadas"
    return
}

Add-Content -Path $logPath -Value "=== inicio $(Get-Date -Format o) | $Condicao | $Modelo | R=$Repeticoes ===" -Encoding utf8

$feitas = 0; $puladas = 0; $falhas = 0
$abortou = $false
$inicio = Get-Date

for ($r = 1; $r -le $Repeticoes; $r++) {
    if ($abortou) { break }
    foreach ($p in $pacotes) {
        $id = [int]($p.BaseName -replace '\D', '')
        $destino = Join-Path $brutosDir ("caso_{0:d2}_run{1}.json" -f $id, $r)

        if (Test-Path $destino) {
            $puladas++
            continue
        }

        $prompt = Get-Content -Path $p.FullName -Raw -Encoding utf8

        try {
            $resposta = $prompt | claude -p `
                --output-format json `
                --model $Modelo `
                --disallowed-tools $semFerramentas `
                --permission-mode plan 2>&1 | Out-String
        }
        catch {
            $resposta = ''
        }

        # Duas formas de falhar, e a segunda e traicoeira: o CLI devolve HTTP 200
        # com um envelope JSON bem-formado carregando "is_error":true (limite de
        # gasto, 429, erro de API). Sem checar isso, o envelope de erro vira
        # arquivo em brutos/, o resumivel pula a chamada pra sempre e o log
        # anuncia falhas=0. Foi o que aconteceu na primeira corrida: 122 de 150.
        $motivo = ''
        if ([string]::IsNullOrWhiteSpace($resposta) -or -not ($resposta.TrimStart().StartsWith('{'))) {
            $motivo = "resposta nao-JSON -> $($resposta.Substring(0, [Math]::Min(200, $resposta.Length)))"
        }
        else {
            try {
                $env = $resposta | ConvertFrom-Json
                if ($env.is_error) {
                    $motivo = "is_error=true status=$($env.api_error_status) terminal=$($env.terminal_reason) :: $($env.result)"
                }
            }
            catch {
                $motivo = "JSON invalido -> $($_.Exception.Message)"
            }
        }

        if ($motivo) {
            $falhas++
            $msg = "FALHA caso $id run $r : $motivo"
            Write-Host $msg -ForegroundColor Red
            Add-Content -Path $logPath -Value $msg -Encoding utf8

            # Limite de gasto nao passa sozinho: continuar so queima o resto da
            # fila com o mesmo 429. Aborta e deixa o resumivel retomar depois.
            if ($resposta -match 'spend limit' -or $resposta -match 'usage limit') {
                # ASCII puro de proposito: o PS 5.1 le .ps1 como ANSI, e um travessao
                # UTF-8 vira o byte 0x94 (aspa curva) que fecha a string na marra.
                $aviso = "ABORTANDO: limite de uso atingido. Levante o limite e rode de novo; o resumivel retoma daqui."
                Write-Host $aviso -ForegroundColor Yellow
                Add-Content -Path $logPath -Value $aviso -Encoding utf8
                $abortou = $true
                break
            }
        }
        else {
            Set-Content -Path $destino -Value $resposta -Encoding utf8 -NoNewline
            $feitas++
            $decorrido = (Get-Date) - $inicio
            Write-Host ("[run {0}] caso {1:d2} ok  ({2} feitas / {3} total, {4:mm\:ss} decorrido)" -f `
                $r, $id, $feitas, $totalChamadas, $decorrido)
        }

        if ($Pausa -gt 0) { Start-Sleep -Milliseconds ([int]($Pausa * 1000)) }
    }
}

$resumo = "=== fim $(Get-Date -Format o) | feitas=$feitas puladas=$puladas falhas=$falhas ==="
Add-Content -Path $logPath -Value $resumo -Encoding utf8
Write-Host ''
Write-Host $resumo
if ($falhas -gt 0) {
    Write-Host "Rode o script de novo: as chamadas que falharam nao gravaram arquivo e serao refeitas." -ForegroundColor Yellow
}
Write-Host "Proximo passo: consolidar_brutos.py, depois comparar.py"
