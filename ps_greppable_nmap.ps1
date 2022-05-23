<#
# Citra IT - Excelência em TI
# PoC of powershell consuming nmap greppable output
# Author: luciano@citrait.com.br
# Date: 22/05/2022
# Usage: Powershell -EP ByPass -File ps_greppable_nmap.ps1
#>
CLS
$MY_PATH = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "Running from: $MY_PATH"


# file with nmap greppable output
$data_file_path = "$MY_PATH\sample_nmap_greppable_output.txt"


# read dat file content into memory
# System.Array[] -> one entry by array index
$RawFileContent = Get-Content -Path $data_file_path

ForEach($line in $RawFileContent)
{
    # fields are separed by tab `t
    $line_fields = $line.split("`t")
    # $line_fields[0] -> Host: 93.95.230.253 ()
    # $line_fields[1] -> Ports: 80/open/tcp//http///, 443/open/tcp//https///
    # $line_fields[2] -> Ignored State: filtered (998)
    
    # extract IP addr
    $ip_addr = [Regex]::Match($line_fields[0], "(?<addr>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})").Groups["addr"].Value
    # Write-Host "Found IPAddr $ip_addr"

    # extract list of open ports
    # $all_open_tcp_ports_matches = [Regex]::Matches($line_fields[1], "(?<addr>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})").Groups["addr"].Value
    $found_ports = $line_fields[1].split(",")
    $open_tcp_ports = @()
    ForEach($port_info in $found_ports)
    {
        $open_tcp_ports += [Int32]::Parse( [regex]::match($port_info, "(?<port>\d+)/open/tcp").Groups["port"].Value )
    }

    $string_ports = [String]::Join(",", $open_tcp_ports)
    Write-Host "$ip_addr Open Ports: $string_ports"

}

