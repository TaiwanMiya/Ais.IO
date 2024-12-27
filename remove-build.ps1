$rootPath = Get-Location

$directoriesToDelete = @(
    ".vs",
    ".github",
    ".vscode",
    "bin",
    "packages",
    "Ais.IO\Debug",
    "Ais.IO\Release",
    "Ais.IO.Command\Debug",
    "Ais.IO.Command\Release",
    "Ais.IO.Debug\x64",
    "Ais.IO.Debug\x86",
    "Ais.IO.Csharp\obj",
    "Ais.IO.Csharp.Command\obj",
    "Sample\Python\__pycache__"
)

foreach ($dir in $directoriesToDelete) {
    $fullPath = Join-Path -Path $rootPath -ChildPath $dir

    if (Test-Path $fullPath) {
        Remove-Item -Path $fullPath -Recurse -Force
    }
}

cmd /c pause