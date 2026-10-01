# Скрипт: собрать все .rs файлы из src и .sql из migrations в один .txt
# Запуск: .\dump_sources.ps1
# Результат: project_dump.txt в корне проекта

$ErrorActionPreference = 'Stop'

$root = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$srcDir = Join-Path $root 'src'
$migrationsDir = Join-Path $root 'migrations'
$outFile = Join-Path $root 'project_dump.txt'

if (-not (Test-Path $srcDir)) {
    Write-Host "ERROR: не найдена папка $srcDir" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $migrationsDir)) {
    Write-Host "ERROR: не найдена папка $migrationsDir" -ForegroundColor Red
    exit 1
}

# Собираем файлы, сортируем по пути для детерминизма
$files = @()
$files += Get-ChildItem -Path $srcDir -Recurse -File -Filter '*.rs'
$files += Get-ChildItem -Path $migrationsDir -Recurse -File -Filter '*.sql'
$files = $files | Sort-Object FullName

Write-Host "Найдено файлов: $($files.Count)" -ForegroundColor Cyan

# Открываем поток записи UTF-8 без BOM
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$stream = [System.IO.File]::Open($outFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
$writer = New-Object System.IO.StreamWriter($stream, $utf8NoBom)

try {
    # Заголовок
    $writer.WriteLine('=' * 80)
    $writer.WriteLine("FRIENDSHUB PROJECT DUMP")
    $writer.WriteLine("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $writer.WriteLine("Files: $($files.Count)")
    $writer.WriteLine('=' * 80)
    $writer.WriteLine()

    $totalLines = 0
    $totalBytes = 0

    foreach ($f in $files) {
        # Относительный путь от корня проекта, с / вместо \
        $rel = $f.FullName.Substring($root.Length).TrimStart('\', '/').Replace('\', '/')

        $writer.WriteLine('=' * 80)
        $writer.WriteLine("FILE: $rel")
        $writer.WriteLine('=' * 80)
        $writer.WriteLine()

        $content = Get-Content -Path $f.FullName -Raw -Encoding UTF8
        if ($null -eq $content) { $content = '' }

        $writer.Write($content)

        # Гарантируем перевод строки в конце файла
        if (-not $content.EndsWith("`n")) {
            $writer.WriteLine()
        }
        $writer.WriteLine()

        $lineCount = ($content -split "`n").Count
        $totalLines += $lineCount
        $totalBytes += $f.Length

        Write-Host ("  + {0} ({1} bytes, {2} lines)" -f $rel, $f.Length, $lineCount) -ForegroundColor DarkGray
    }

    # Итоговая статистика
    $writer.WriteLine('=' * 80)
    $writer.WriteLine("TOTAL: $($files.Count) files, $totalLines lines, $totalBytes bytes")
    $writer.WriteLine('=' * 80)

    Write-Host ""
    Write-Host "Готово:" -ForegroundColor Green
    Write-Host "  Файл:      $outFile"
    Write-Host "  Размер:    $((Get-Item $outFile).Length) bytes"
    Write-Host "  Файлов:    $($files.Count)"
    Write-Host "  Строк:     $totalLines"
}
finally {
    $writer.Close()
    $stream.Close()
}