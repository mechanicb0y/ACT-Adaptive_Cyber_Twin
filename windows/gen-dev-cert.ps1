<#
.SYNOPSIS
    Self-signed certificate for local HTTPS on Windows.
.DESCRIPTION
    Uses openssl if present (matches the Linux script exactly); otherwise falls
    back to New-SelfSignedCertificate + export. Writes
    backend\data\tls\dev-cert.pem and dev-key.pem.

    ACT also generates this pair on its own when ACT_SSL_ENABLED=true and no
    ACT_SSL_CERT is set, so you usually do not need to run this.
.EXAMPLE
    .\windows\gen-dev-cert.ps1 -CommonName localhost
#>
param([string] $CommonName = "localhost")

$ErrorActionPreference = "Stop"
$dir = Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..")).Path "backend\data\tls"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$cert = Join-Path $dir "dev-cert.pem"
$key  = Join-Path $dir "dev-key.pem"

if (Get-Command openssl -ErrorAction SilentlyContinue) {
    & openssl req -x509 -newkey rsa:2048 -nodes -keyout $key -out $cert `
        -days 825 -subj "/CN=$CommonName" `
        -addext "subjectAltName=DNS:$CommonName,DNS:localhost,IP:127.0.0.1"
}
else {
    Write-Host "openssl not found; using New-SelfSignedCertificate"
    $c = New-SelfSignedCertificate -DnsName $CommonName, "localhost" `
        -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddMonths(27) `
        -KeyExportPolicy Exportable
    $pwd = ConvertTo-SecureString -String "act" -Force -AsPlainText
    $pfx = Join-Path $dir "dev.pfx"
    Export-PfxCertificate -Cert $c -FilePath $pfx -Password $pwd | Out-Null
    # convert to PEM via .NET (no openssl)
    $col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $col.Import($pfx, "act", "Exportable")
    $leaf = $col[0]
    $pem  = "-----BEGIN CERTIFICATE-----`n" +
            [Convert]::ToBase64String($leaf.RawData, "InsertLineBreaks") +
            "`n-----END CERTIFICATE-----`n"
    Set-Content -Path $cert -Value $pem -Encoding ascii
    $rsa   = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($leaf)
    $bytes = $rsa.ExportPkcs8PrivateKey()
    $kpem  = "-----BEGIN PRIVATE KEY-----`n" +
             [Convert]::ToBase64String($bytes, "InsertLineBreaks") +
             "`n-----END PRIVATE KEY-----`n"
    Set-Content -Path $key -Value $kpem -Encoding ascii
    Remove-Item $pfx -Force
}

Write-Host "wrote $cert and $key (self-signed; browsers will warn)"
