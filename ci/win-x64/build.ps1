$RequiredRustToolchain = $(cat ./rust-toolchain)

Invoke-WebRequest -OutFile ./rustup-init.exe -Uri https://win.rustup.rs
& ./rustup-init.exe --default-host x86_64-pc-windows-msvc --default-toolchain $RequiredRustToolchain -y
if ($LASTEXITCODE) { exit 1 }

$env:Path = "$HOME\.cargo\bin;$env:Path"

Push-Location "$PSScriptRoot/../../"

. "./ci/build-deps.ps1"

$version = Get-SemVer

Initialize-Filesystem
Invoke-WindowsBuild
Invoke-WindowsTests
# NOTE: We're relying on GitHub Actions to copy the linux binaries across here instead of building locally
# Invoke-LinuxBuild
Invoke-NuGetPack ($version)

if ($env:CI_EVENT -eq "push" -and $env:NUGET_API_KEY -ne "") {
    Publish-NuPkg ($version)

    if ($env:CI_TARGET_BRANCH -eq "release") {
        Publish-GitHubRelease ($version)
    }
}
else {
    Write-Output "Not publishing NUPKG or GitHub release"
}

Pop-Location
