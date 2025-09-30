# Script di disinstallazione completo per il client C2
# Questo script rimuove tutti i file, voci di registro e task schedulati

Write-Host "[INFO] Avvio disinstallazione client C2..." -ForegroundColor Yellow

# 1. TERMINA IL PROCESSO CLIENT SE IN ESECUZIONE
Write-Host "[1/5] Terminazione processi client..." -ForegroundColor Cyan
$processNames = @("client_c2", "client_c2_test", "client_c2_debug", "UpdateCore")
foreach ($procName in $processNames) {
    $processes = Get-Process -Name $procName -ErrorAction SilentlyContinue
    if ($processes) {
        Write-Host "   Terminando processo: $procName" -ForegroundColor Red
        Stop-Process -Name $procName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
}

# 2. RIMUOVI FILE E CARTELLE
Write-Host "[2/5] Rimozione file e cartelle..." -ForegroundColor Cyan
$filesToRemove = @(
    "client_c2.exe",
    "client_c2_test.exe", 
    "client_c2_debug.exe",
    "lab_client_redt_advanced.obj"
)

foreach ($file in $filesToRemove) {
    if (Test-Path $file) {
        Write-Host "   Eliminando: $file" -ForegroundColor Red
        Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
    }
}

# 3. RIMUOVI VOCI DI REGISTRO
Write-Host "[3/5] Pulizia registro di sistema..." -ForegroundColor Cyan
try {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    if (Test-Path $regPath) {
        $value = Get-ItemProperty -Path $regPath -Name "UpdateCore" -ErrorAction SilentlyContinue
        if ($value) {
            Write-Host "   Rimuovendo voce registro: UpdateCore" -ForegroundColor Red
            Remove-ItemProperty -Path $regPath -Name "UpdateCore" -ErrorAction SilentlyContinue
        }
    }
} catch {
    Write-Host "   [WARN] Impossibile accedere al registro" -ForegroundColor Yellow
}

# 4. RIMUOVI TASK SCHEDULATI
Write-Host "[4/5] Rimozione task schedulati..." -ForegroundColor Cyan
try {
    $taskName = "WindowsUpdate"
    $taskExists = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($taskExists) {
        Write-Host "   Rimuovendo task: $taskName" -ForegroundColor Red
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
} catch {
    Write-Host "   [WARN] Impossibile rimuovere task schedulato" -ForegroundColor Yellow
}

# 5. PULIZIA VARIABILI AMBIENTE
Write-Host "[5/5] Pulizia variabili ambiente..." -ForegroundColor Cyan
try {
    if ($env:DEBUG) {
        Write-Host "   Rimuovendo variabile DEBUG" -ForegroundColor Red
        Remove-Item Env:\DEBUG -ErrorAction SilentlyContinue
    }
} catch {
    Write-Host "   [WARN] Impossibile rimuovere variabili ambiente" -ForegroundColor Yellow
}

# VERIFICA FINALE
Write-Host "`n[VERIFICA] Controllo residui..." -ForegroundColor Green

# Verifica processi
$runningProcesses = Get-Process | Where-Object { $_.ProcessName -like "*client*" -or $_.ProcessName -like "*UpdateCore*" }
if (-not $runningProcesses) {
    Write-Host "   Nessun processo client in esecuzione" -ForegroundColor Green
} else {
    Write-Host "   Processi ancora attivi: $($runningProcesses.ProcessName)" -ForegroundColor Red
}

# Verifica file
$remainingFiles = Get-ChildItem -File | Where-Object { $_.Name -like "*client*" -or $_.Name -like "*lab_client*" }
if (-not $remainingFiles) {
    Write-Host "   Nessun file client residuo" -ForegroundColor Green
} else {
    Write-Host "   File residui trovati: $($remainingFiles.Name)" -ForegroundColor Red
}

Write-Host "`n[COMPLETATO] Disinstallazione completata!" -ForegroundColor Green
Write-Host "Si consiglia riavvio del sistema per completare la pulizia." -ForegroundColor Magenta