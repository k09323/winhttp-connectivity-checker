# ===============================
# WinHTTP Error Code Mapping
# ===============================
$WinHttpErrors = @{
    12001 = @{ Name = "ERROR_WINHTTP_OUT_OF_HANDLES"; Suggestion = "Internal error. Restart script." }
    12002 = @{ Name = "ERROR_WINHTTP_TIMEOUT"; Suggestion = "Connection timed out. Check network path, firewall, proxy." }
    12004 = @{ Name = "ERROR_WINHTTP_INTERNAL_ERROR"; Suggestion = "Internal WinHTTP error." }
    12005 = @{ Name = "ERROR_WINHTTP_INVALID_URL"; Suggestion = "The URL format is invalid." }
    12007 = @{ Name = "ERROR_WINHTTP_NAME_NOT_RESOLVED"; Suggestion = "DNS cannot resolve the hostname. Check DNS settings." }
    12029 = @{ Name = "ERROR_WINHTTP_CANNOT_CONNECT"; Suggestion = "TCP connection failed. Check firewall, port 443 access." }
    12037 = @{ Name = "ERROR_WINHTTP_SECURE_CERT_DATE_INVALID"; Suggestion = "Certificate expired or not yet valid. Check system clock and cert expiry." }
    12038 = @{ Name = "ERROR_WINHTTP_SECURE_CERT_CN_INVALID"; Suggestion = "Certificate hostname mismatch. Possibly a proxy is intercepting." }
    12044 = @{ Name = "ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED"; Suggestion = "Server requires a client certificate." }
    12045 = @{ Name = "ERROR_WINHTTP_SECURE_INVALID_CA"; Suggestion = "Root CA not trusted. Install the CA cert in LocalMachine\\Root store." }
    12057 = @{ Name = "ERROR_WINHTTP_SECURE_CERT_REV_FAILED"; Suggestion = "Revocation check failed. CRL/OCSP endpoint may be unreachable." }
    12169 = @{ Name = "ERROR_WINHTTP_SECURE_INVALID_CERT"; Suggestion = "Certificate is invalid (generic). Check cert details below." }
    12175 = @{ Name = "ERROR_WINHTTP_SECURE_FAILURE"; Suggestion = "TLS/SSL failure. Check TLS version support and proxy config." }
    12178 = @{ Name = "ERROR_WINHTTP_AUTO_PROXY_SERVICE_ERROR"; Suggestion = "WinHTTP auto-proxy (WPAD) failed. Check proxy settings." }
}

# ===============================
# INPUT URL
# ===============================
$inputUrl = Read-Host "Please enter HTTPS URL (e.g. https://node16.xensor.ai/)"

if ($inputUrl -notmatch "^https?://") {
    Write-Host "Invalid URL format. Please include http:// or https://" -ForegroundColor Red
    exit
}

$uri = [System.Uri]$inputUrl
$hostName = $uri.Host
$port = if ($uri.Port -gt 0) { $uri.Port } else { 443 }

# ===============================
# ROOT CA CHECK
# ===============================
$targets = @(
    "DigiCert Trusted Root G4",
    "DigiCert Assured ID Root CA",
    "Microsoft Root Certificate Authority 2010"
)

Write-Host "`n===== LOCAL ROOT CA CHECK =====" -ForegroundColor Yellow

$store = Get-ChildItem Cert:\LocalMachine\Root

foreach ($target in $targets) {
    Write-Host "==== Checking: $target ====" -ForegroundColor Cyan

    $found = $store | Where-Object { $_.Subject -like "*$target*" } | Sort-Object Thumbprint -Unique

    if ($found) {
        foreach ($cert in $found) {
            Write-Host "[FOUND]" -ForegroundColor Green
            Write-Host "  Subject     : $($cert.Subject)"
            Write-Host "  Issuer      : $($cert.Issuer)"
            Write-Host "  Thumbprint  : $($cert.Thumbprint)"
            Write-Host "  Expires     : $($cert.NotAfter)"
            Write-Host ""
        }
    } else {
        Write-Host "[NOT FOUND]" -ForegroundColor Red
        Write-Host ""
    }
}

# ===============================
# WINHTTP PROXY SETTINGS
# ===============================
Write-Host "===== WINHTTP PROXY CONFIGURATION =====" -ForegroundColor Yellow

try {
    $proxyOutput = netsh winhttp show proxy 2>&1
    Write-Host $proxyOutput
} catch {
    Write-Host "[WARN] Could not retrieve WinHTTP proxy settings: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Compare with IE/system proxy
try {
    $ieProxyEnable = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -ErrorAction SilentlyContinue
    $ieProxyServer = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -ErrorAction SilentlyContinue

    if ($ieProxyEnable.ProxyEnable -eq 1) {
        Write-Host "`n[INFO] IE/System proxy is ENABLED: $($ieProxyServer.ProxyServer)" -ForegroundColor Cyan
        Write-Host "  Note: WinHTTP (used by agents) does NOT use IE proxy unless imported via 'netsh winhttp import proxy source=ie'" -ForegroundColor Cyan
    } else {
        Write-Host "`n[INFO] IE/System proxy is disabled." -ForegroundColor Cyan
    }
} catch {
    # Ignore registry read errors
}

Write-Host ""

# ===============================
# TCP CONNECTIVITY CHECK
# ===============================
Write-Host "===== TCP CONNECTIVITY CHECK =====" -ForegroundColor Yellow

$ports = @(80, 443)

foreach ($p in $ports) {
    Write-Host "Checking $hostName : Port $p ..." -ForegroundColor Cyan

    $result = Test-NetConnection -ComputerName $hostName -Port $p -WarningAction SilentlyContinue

    if ($result.TcpTestSucceeded) {
        Write-Host "[OPEN]" -ForegroundColor Green
    } else {
        Write-Host "[FAILED]" -ForegroundColor Red
    }

    Write-Host ""
}

# ===============================
# WINHTTP HTTPS CONNECTIVITY TEST
# ===============================
Write-Host "===== WINHTTP HTTPS CONNECTIVITY TEST (Authoritative) =====" -ForegroundColor Yellow
Write-Host "Testing: $inputUrl" -ForegroundColor Cyan
Write-Host "This uses WinHttp.WinHttpRequest.5.1 COM, same as Windows agents/services." -ForegroundColor Cyan
Write-Host ""

$winhttp = $null
try {
    $winhttp = New-Object -ComObject WinHttp.WinHttpRequest.5.1
    $winhttp.SetTimeouts(10000, 10000, 10000, 10000)

    # Set TLS 1.2 + TLS 1.3
    # Option(9) = WinHttpRequestOption_SecureProtocols
    # 0x800 = TLS 1.2, 0x2000 = TLS 1.3
    $winhttp.Option(9) = 0x00000800 -bor 0x00002000

    $winhttp.Open("GET", $inputUrl, $false)
    $winhttp.Send()

    $statusCode = $winhttp.Status
    $statusText = $winhttp.StatusText

    Write-Host "[PASS] WinHTTP connection succeeded" -ForegroundColor Green
    Write-Host "  HTTP Status : $statusCode $statusText"
    Write-Host "  Headers     :"
    Write-Host $winhttp.GetAllResponseHeaders()
}
catch {
    $hresult = $_.Exception.HResult
    $errorCode = [int64]$hresult -band 0xFFFF
    $errorMsg = $_.Exception.Message

    Write-Host "[FAIL] WinHTTP connection failed" -ForegroundColor Red
    Write-Host "  Error Code  : $errorCode"
    Write-Host "  Message     : $errorMsg"

    if ($WinHttpErrors.ContainsKey([int]$errorCode)) {
        $info = $WinHttpErrors[[int]$errorCode]
        Write-Host "  Error Name  : $($info.Name)" -ForegroundColor Yellow
        Write-Host "  Suggestion  : $($info.Suggestion)" -ForegroundColor Yellow
    }
}
finally {
    if ($winhttp) {
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($winhttp) | Out-Null
    }
}

Write-Host ""

# ===============================
# CERTIFICATE DETAILS (via HttpWebRequest - diagnostic only)
# ===============================
Write-Host "===== CERTIFICATE DETAILS (via .NET HttpWebRequest - Diagnostic Info) =====" -ForegroundColor Yellow
Write-Host "NOTE: This section displays certificate details that WinHTTP COM does not expose." -ForegroundColor Cyan
Write-Host "      The authoritative connectivity result is the WinHTTP test above." -ForegroundColor Cyan
Write-Host ""

try {
    $req = [System.Net.HttpWebRequest]::Create($inputUrl)
    $req.Method = "HEAD"
    $req.Timeout = 15000

    $resp = $req.GetResponse()
    $resp.Close()

    $cert = $req.ServicePoint.Certificate
    $remoteCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert)

    Write-Host "[Server Certificate]" -ForegroundColor Green
    Write-Host "  Subject     : $($remoteCert.Subject)"
    Write-Host "  Issuer      : $($remoteCert.Issuer)"
    Write-Host "  Thumbprint  : $($remoteCert.Thumbprint)"
    Write-Host "  Serial      : $($remoteCert.SerialNumber)"
    Write-Host "  NotBefore   : $($remoteCert.NotBefore)"
    Write-Host "  NotAfter    : $($remoteCert.NotAfter)"
    Write-Host ""

    # Display certificate chain
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.Build($remoteCert) | Out-Null

    Write-Host "[Certificate Chain]" -ForegroundColor Green
    $i = 0
    foreach ($elem in $chain.ChainElements) {
        $prefix = "  " + ("  " * $i)
        Write-Host "${prefix}[$i] $($elem.Certificate.Subject)"
        Write-Host "${prefix}    Issuer     : $($elem.Certificate.Issuer)"
        Write-Host "${prefix}    Thumbprint : $($elem.Certificate.Thumbprint)"
        Write-Host "${prefix}    Expires    : $($elem.Certificate.NotAfter)"
        $i++
    }

    if ($chain.ChainStatus.Count -gt 0) {
        Write-Host ""
        Write-Host "[Chain Validation Issues]" -ForegroundColor Yellow
        foreach ($status in $chain.ChainStatus) {
            Write-Host "  $($status.Status): $($status.StatusInformation)" -ForegroundColor Yellow
        }
    }
}
catch {
    Write-Host "[FAIL] Could not retrieve certificate details" -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)"
    Write-Host "  Refer to the TCP and WinHTTP results above for connectivity diagnosis."
}
