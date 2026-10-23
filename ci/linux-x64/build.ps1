$RequiredRustToolchain = $(cat ./rust-toolchain)

curl https://sh.rustup.rs -sSf | sh -s -- --default-host x86_64-unknown-linux-gnu --default-toolchain $RequiredRustToolchain -y

$env:PATH = "$HOME/.cargo/bin:$env:PATH"

& rustup target add x86_64-unknown-linux-musl
if ($LASTEXITCODE) { exit 1 }

& rustup target add aarch64-unknown-linux-musl
if ($LASTEXITCODE) { exit 1 }

Push-Location "$PSScriptRoot/../../"

. "./ci/build-deps.ps1"

$version = Get-SemVer

function Invoke-SmokeTest($protocol, $format) {
    Write-BeginStep $MYINVOCATION

    $finished = $false
    $retries = 0

    do {
        try {
            Start-SeqEnvironment $protocol
            Invoke-TestApp $protocol $format
            Check-SquiflogLogs
            Check-SeqLogs
            Check-ClefOutput

            $finished = $true
        }
        catch {
            Stop-SeqEnvironment

            if ($retries -gt 3) {
                exit 1
            }
            else {
                $retries = $retries + 1
                Write-Host "Retrying (attempt $retries)"
            }
        }
        
    }
    while ($finished -eq $false)

    Stop-SeqEnvironment
}

Initialize-Filesystem
Invoke-LinuxBuild
Invoke-LinuxTests
Invoke-DockerBuild

Build-TestAppContainer

Invoke-SmokeTest "udp" "rfc5424"
Invoke-SmokeTest "udp" "rfc3164"

if ($env:CI_EVENT -eq "push" -and $env:DOCKER_TOKEN -ne "") {
    Publish-Container ($version)
}
else {
    Write-Output "Not publishing Docker container"
}

Pop-Location
