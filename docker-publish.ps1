param (
  [Parameter(Mandatory=$true)]
  [string] $version
)

$versionParts = $version.Split('.')

$major = $versionParts[0]
$minor = $versionParts[1]

$baseImage = "datalust/squiflog-ci:$version"
$publishImages = "datalust/squiflog:latest", "datalust/squiflog:$major", "datalust/squiflog:$major.$minor", "datalust/squiflog:$version", "datalust/seq-input-syslog:latest", "datalust/seq-input-syslog:$major", "datalust/seq-input-syslog:$major.$minor", "datalust/seq-input-syslog:$version"

$choices  = "&Yes", "&No"
$decision = $Host.UI.PromptForChoice("Publishing ($baseImage) as ($publishImages)", "Does this look right?", $choices, 1)
if ($decision -eq 0) {
    foreach ($publishImage in $publishImages) {
        Write-Host "Publishing $publishImage"

        docker tag $baseImage $publishImage
        if ($LASTEXITCODE) { exit 1 }

        docker push $publishImage
        if ($LASTEXITCODE) { exit 1 }
    }
} else {
    Write-Host "Cancelled"
}
