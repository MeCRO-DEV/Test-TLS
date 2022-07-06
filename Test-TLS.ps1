###############################################
# Test SSL/TLS connection/handshake           #
# Author: David Wang                          #
# usage: Test-TLS.ps1 SERVER_NAME PORT_NUMBER #
# Date: Jun 2022                              #
# Note: To get more info, please run it on    #
# the latest version of Powershell Core       #
###############################################
# The MIT License (MIT)
#
# Copyright (c) 2022, David Wang
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and 
# associated documentation files (the "Software"), to deal in the Software without restriction, 
# including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
# and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial
# portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
# LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.#>
###############################################################################################################
function Test-TLS {
    param(
        [string]$ServerName,
        [UInt16]$Port
    )

    $P = New-Object psobject -Property @{
        Host = $ServerName
        Port = $Port
        SSLv2 = $false
        SSLv3 = $false
        TLSv1_0 = $false
        TLSv1_1 = $false
        TLSv1_2 = $false
        TLSv1_3 = $false
        KeyExhange_SSLv2 = $null
        KeyExhange_SSLv3 = $null
        KeyExhange_TLSv1_0 = $null
        KeyExhange_TLSv1_1 = $null
        KeyExhange_TLSv1_2 = $null
        KeyExhange_TLSv1_3 = $null
        HashAlgorithm_SSLv2 = $null
        HashAlgorithm_SSLv3 = $null
        HashAlgorithm_TLSv1_0 = $null
        HashAlgorithm_TLSv1_1 = $null
        HashAlgorithm_TLSv1_2 = $null
        HashAlgorithm_TLSv1_3 = $null
    }

    [Net.Security.SslStream]$SslStream_SSLv2   = $null
    [Net.Security.SslStream]$SslStream_SSLv3   = $null
    [Net.Security.SslStream]$SslStream_TLSv1_0 = $null
    [Net.Security.SslStream]$SslStream_TLSv1_1 = $null
    [Net.Security.SslStream]$SslStream_TLSv1_2 = $null
    [Net.Security.SslStream]$SslStream_TLSv1_3 = $null
    [Net.Sockets.TcpClient]$TcpClient_SSLv2    = $null
    [Net.Sockets.TcpClient]$TcpClient_SSLv3    = $null
    [Net.Sockets.TcpClient]$TcpClient_TLSv1_0  = $null
    [Net.Sockets.TcpClient]$TcpClient_TLSv1_1  = $null
    [Net.Sockets.TcpClient]$TcpClient_TLSv1_2  = $null
    [Net.Sockets.TcpClient]$TcpClient_TLSv1_3  = $null

    "ssl2", "ssl3", "tls", "tls11", "tls12", "tls13" | % {
        switch ($_) {
            "ssl2"  {
                $TcpClient_SSLv2 = New-Object Net.Sockets.TcpClient
                $TcpClient_SSLv2.Connect($P.Host, $P.Port)
                $SslStream_SSLv2 = New-Object Net.Security.SslStream $TcpClient_SSLv2.GetStream()
                $SslStream_SSLv2.ReadTimeout  = 15000
                $SslStream_SSLv2.WriteTimeout = 15000
                try {
                    $SslStream_SSLv2.AuthenticateAsClient($P.Host,$null,$_,$false)
                    $P.KeyExhange_SSLv2 = $SslStream_SSLv2.KeyExchangeAlgorithm
                    $P.HashAlgorithm_SSLv2 = $SslStream_SSLv2.HashAlgorithm
                    $status = $true
                } catch {
                    $status = $false
                }
                $P.SSLv2   = $status;
            }
            "ssl3"  {
                $TcpClient_SSLv3 = New-Object Net.Sockets.TcpClient
                $TcpClient_SSLv3.Connect($P.Host, $P.Port)
                $SslStream_SSLv3 = New-Object Net.Security.SslStream $TcpClient_SSLv3.GetStream()
                $SslStream_SSLv3.ReadTimeout  = 15000
                $SslStream_SSLv3.WriteTimeout = 15000
                try {
                    $SslStream_SSLv3.AuthenticateAsClient($P.Host,$null,$_,$false)
                    $P.KeyExhange_SSLv3 = $SslStream_SSLv3.KeyExchangeAlgorithm
                    $P.HashAlgorithm_SSLv3 = $SslStream_SSLv3.HashAlgorithm
                    $status = $true
                } catch {
                    $status = $false
                }
                $P.SSLv3   = $status;
            }
            "tls"   {
                $TcpClient_TLSv1_0 = New-Object Net.Sockets.TcpClient
                $TcpClient_TLSv1_0.Connect($P.Host, $P.Port)
                $SslStream_TLSv1_0 = New-Object Net.Security.SslStream $TcpClient_TLSv1_0.GetStream()
                $SslStream_TLSv1_0.ReadTimeout  = 15000
                $SslStream_TLSv1_0.WriteTimeout = 15000
                try {
                    $SslStream_TLSv1_0.AuthenticateAsClient($P.Host,$null,$_,$false)
                    $P.KeyExhange_TLSv1_0 = $SslStream_TLSv1_0.KeyExchangeAlgorithm
                    $P.HashAlgorithm_TLSv1_0 = $SslStream_TLSv1_0.HashAlgorithm
                    $status = $true
                } catch {
                    $status = $false
                }
                $P.TLSv1_0   = $status;
            }
            "tls11" {
                $TcpClient_TLSv1_1 = New-Object Net.Sockets.TcpClient
                $TcpClient_TLSv1_1.Connect($P.Host, $P.Port)
                $SslStream_TLSv1_1 = New-Object Net.Security.SslStream $TcpClient_TLSv1_1.GetStream()
                $SslStream_TLSv1_1.ReadTimeout  = 15000
                $SslStream_TLSv1_1.WriteTimeout = 15000
                try {
                    $SslStream_TLSv1_1.AuthenticateAsClient($P.Host,$null,$_,$false)
                    $P.KeyExhange_TLSv1_1 = $SslStream_TLSv1_1.KeyExchangeAlgorithm
                    $P.HashAlgorithm_TLSv1_1 = $SslStream_TLSv1_1.HashAlgorithm
                    $status = $true
                } catch {
                    $status = $false
                }
                $P.TLSv1_1   = $status;
            }
            "tls12" {
                $TcpClient_TLSv1_2 = New-Object Net.Sockets.TcpClient
                $TcpClient_TLSv1_2.Connect($P.Host, $P.Port)
                $SslStream_TLSv1_2 = New-Object Net.Security.SslStream $TcpClient_TLSv1_2.GetStream()
                $SslStream_TLSv1_2.ReadTimeout  = 15000
                $SslStream_TLSv1_2.WriteTimeout = 15000
                try {
                    $SslStream_TLSv1_2.AuthenticateAsClient($P.Host,$null,$_,$false)
                    $P.KeyExhange_TLSv1_2 = $SslStream_TLSv1_2.KeyExchangeAlgorithm
                    $P.HashAlgorithm_TLSv1_2 = $SslStream_TLSv1_2.HashAlgorithm
                    $status = $true
                } catch {
                    $status = $false
                }
                $P.TLSv1_2   = $status;
            }
            "tls13" {
                $TcpClient_TLSv1_3 = New-Object Net.Sockets.TcpClient
                $TcpClient_TLSv1_3.Connect($P.Host, $P.Port)
                $SslStream_TLSv1_3 = New-Object Net.Security.SslStream $TcpClient_TLSv1_3.GetStream()
                $SslStream_TLSv1_3.ReadTimeout  = 15000
                $SslStream_TLSv1_3.WriteTimeout = 15000
                try {
                    $SslStream_TLSv1_3.AuthenticateAsClient($P.Host,$null,$_,$false)
                    $P.KeyExhange_TLSv1_3 = $SslStream_TLSv1_3.KeyExchangeAlgorithm
                    $P.HashAlgorithm_TLSv1_3 = $SslStream_TLSv1_3.HashAlgorithm
                    $status = $true
                } catch {
                    $status = $false
                }
                $P.TLSv1_3   = $status;
            }
        }
    }

    Write-Host -Foreground Green "     "
    Write-Host -Foreground Green "=== SSL/TLS Connection Testing Result ==="
    Write-Host -Foreground Green "     "

    Write-Host -Foreground Green "- Summary -"
    Write-Host -Foreground Cyan "Target        = " -NoNewLine
    Write-Host -Foreground Cyan "$ServerName : $Port"
    Write-Host -Foreground Cyan "SSLv2         = " -NoNewLine
    Write-Host -Foreground (&{If($P.SSLv2) {"Green"} Else {"Yellow"}}) $P.SSLv2
    Write-Host -Foreground Cyan "SSLv3         = " -NoNewLine
    Write-Host -Foreground (&{If($P.SSLv3) {"Green"} Else {"Yellow"}}) $P.SSLv3
    Write-Host -Foreground Cyan "TLSv1.0       = " -NoNewLine
    Write-Host -Foreground (&{If($P.TLSv1_0) {"Green"} Else {"Yellow"}}) $P.TLSv1_0
    Write-Host -Foreground Cyan "TLSv1.1       = " -NoNewLine
    Write-Host -Foreground (&{If($P.TLSv1_1) {"Green"} Else {"Yellow"}}) $P.TLSv1_1
    Write-Host -Foreground Cyan "TLSv1.2       = " -NoNewLine
    Write-Host -Foreground (&{If($P.TLSv1_2) {"Green"} Else {"Yellow"}}) $P.TLSv1_2
    Write-Host -Foreground Cyan "TLSv1.3       = " -NoNewLine
    Write-Host -Foreground (&{If($P.TLSv1_3) {"Green"} Else {"Yellow"}}) $P.TLSv1_3
    if($P.SSLv2){
        Write-Host -Foreground Cyan "KeyExhange(SSLv2)    = " -NoNewLine
        Write-Host -Foreground Cyan $P.KeyExhange_SSLv2
        Write-Host -Foreground Cyan "HashAlgorithm(SSLv2) = " -NoNewLine
        Write-Host -Foreground Cyan $P.HashAlgorithm_SSLv2
    }
    if($P.SSLv3){
        Write-Host -Foreground Cyan "KeyExhange(SSLv3)    = " -NoNewLine
        Write-Host -Foreground Cyan $P.KeyExhange_SSLv3
        Write-Host -Foreground Cyan "HashAlgorithm(SSLv3) = " -NoNewLine
        Write-Host -Foreground Cyan $P.HashAlgorithm_SSLv3
    }
    if($P.TLSv1_0){
        Write-Host -Foreground Cyan "KeyExhange(TLSv1.0)    = " -NoNewLine
        Write-Host -Foreground Cyan $P.KeyExhange_TLSv1_0
        Write-Host -Foreground Cyan "HashAlgorithm(TLSv1.0) = " -NoNewLine
        Write-Host -Foreground Cyan $P.HashAlgorithm_TLSv1_0
    }
    if($P.TLSv1_1){
        Write-Host -Foreground Cyan "KeyExhange(TLSv1.1)    = " -NoNewLine
        Write-Host -Foreground Cyan $P.KeyExhange_TLSv1_1
        Write-Host -Foreground Cyan "HashAlgorithm(TLSv1.1) = " -NoNewLine
        Write-Host -Foreground Cyan $P.HashAlgorithm_TLSv1_1
    }
    if($P.TLSv1_2){
        Write-Host -Foreground Cyan "KeyExhange(TLSv1.2)    = " -NoNewLine
        Write-Host -Foreground Cyan $P.KeyExhange_TLSv1_2
        Write-Host -Foreground Cyan "HashAlgorithm(TLSv1.2) = " -NoNewLine
        Write-Host -Foreground Cyan $P.HashAlgorithm_TLSv1_2
    }
    if($P.TLSv1_3){
        Write-Host -Foreground Cyan "KeyExhange(TLSv1.3)    = " -NoNewLine
        Write-Host -Foreground Cyan $P.KeyExhange_TLSv1_3
        Write-Host -Foreground Cyan "HashAlgorithm(TLSv1.3) = " -NoNewLine
        Write-Host -Foreground Cyan $P.HashAlgorithm_TLSv1_3
    }

    if($P.SSLv2){
        Write-Host -Foreground Green "      "
        Write-Host -Foreground Green "- Handshake Detail : SSLv2-" -NoNewLine
        $SslStream_SSLv2 | Format-List -Property *
    }
    
    if($P.SSLv3){
        Write-Host -Foreground Green "      "
        Write-Host -Foreground Green "- Handshake Detail : SSLv3 -" -NoNewLine
        $SslStream_SSLv3 | Format-List -Property *
    }

    if($P.TLSv1_0){
        Write-Host -Foreground Green "      "
        Write-Host -Foreground Green "- Handshake Detail : TLSv1.0 -" -NoNewLine
        $SslStream_TLSv1_0 | Format-List -Property *
    }

    if($P.TLSv1_1){
        Write-Host -Foreground Green "      "
        Write-Host -Foreground Green "- Handshake Detail : TLSv1.1 -" -NoNewLine
        $SslStream_TLSv1_1 | Format-List -Property *
    }

    if($P.TLSv1_2){
        Write-Host -Foreground Green "      "
        Write-Host -Foreground Green "- Handshake Detail : TLSv1.2 -" -NoNewLine
        $SslStream_TLSv1_2 | Format-List -Property *
    }

    if($P.TLSv1_3){
        Write-Host -Foreground Green "      "
        Write-Host -Foreground Green "- Handshake Detail : TLSv1.3 -" -NoNewLine
        $SslStream_TLSv1_3 | Format-List -Property *
    }

    $TcpClient_SSLv2.Dispose()
    $TcpClient_SSLv3.Dispose()
    $TcpClient_TLSv1_0.Dispose()
    $TcpClient_TLSv1_1.Dispose()
    $TcpClient_TLSv1_2.Dispose()
    $TcpClient_TLSv1_3.Dispose()
    $SslStream_SSLv2.Dispose()
    $SslStream_SSLv3.Dispose()
    $SslStream_TLSv1_0.Dispose()
    $SslStream_TLSv1_1.Dispose()
    $SslStream_TLSv1_2.Dispose()
    $SslStream_TLSv1_3.Dispose()
}

if($args.length -ne 2) {
    Write-Host -Foreground Red "Missing arguments."
    Write-Host -Foreground Cyan "Usage: .\TLS-Test.ps1 SERVER_NAME PORT_NUMBER"
    exit
}

$SN = $args[0]
$PN = $args[1]

Write-Host -Foreground Green "=== Server Name Lookup ==="
try {
        $test = Resolve-DnsName $SN 2>$null 3>$null
    } catch {
}

if(!$test -eq $null){
    Write-Host -Foreground Red "Wrong server name: $SN"
    exit
} Else {
    $test
}

try {
        $test = Test-NetConnection -ComputerName $SN -Port $PN 2>$null 3>$null
    } catch {
}

if(!$test.TcpTestSucceeded){
    Write-Host -Foreground Red "Port $PN unreachable on $SN"
    exit
} Else {
    Test-TLS -ServerName $SN -Port $PN
    Write-Host -Foreground Green "= End ="
}