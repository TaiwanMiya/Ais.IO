$rootPath = Get-Location

$directoriesToDelete = @(
    ".vs",
    ".github",
    "bin",
    "packages",
    "Ais.IO\obj",
    "Ais.IO.Command\obj",
    "Ais.IO.Source\Debug",
    "Ais.IO.Source\Release"
)

foreach ($dir in $directoriesToDelete) {
    $fullPath = Join-Path -Path $rootPath -ChildPath $dir

    if (Test-Path $fullPath) {
        Remove-Item -Path $fullPath -Recurse -Force
    }
}

cmd /c pause