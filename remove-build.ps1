$rootPath = Get-Location

$directoriesToDelete = @(
    ".vs",
    ".github",
    "bin",
    "packages",
    "Ais.IO\obj",
    "Ais.IO\Debug",
    "Ais.IO\Release",
    "Ais.IO.Command\obj",
    "Ais.IO.Csharp\obj",
    "Ais.IO.Win32.Console\Debug",
    "Ais.IO.Win32.Console\Release"
)

foreach ($dir in $directoriesToDelete) {
    $fullPath = Join-Path -Path $rootPath -ChildPath $dir

    if (Test-Path $fullPath) {
        Remove-Item -Path $fullPath -Recurse -Force
    }
}

cmd /c pause