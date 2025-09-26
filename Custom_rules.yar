
rule AV_ReverseShell_IVI {
  meta:
    author      = "Alexander"
    description = "Detects Python reverse-shell patterns in IVI applications"
    severity    = "high"
  strings:
    $s1 = "import socket" wide ascii
    $s2 = "connect((" ascii
    $s3 = "dup2(" ascii
    $s4 = "/bin/sh" ascii
  condition:
    all of ($s*) and filesize < 1MB
}

rule AV_Firmware_Tamper {
  meta:
    author      = "Alexander"
    description = "Catches non-signed or malformed firmware update carriers"
    severity    = "high"
  strings:
    $hdr_magic   = { 46 57 55 50 }    
    $no_signature = "SIGNATURE_OFFSET=0" ascii
  condition:
    $hdr_magic at 0 and $no_signature
}

rule AV_Config_Manipulation {
  meta:
    author      = "Alexander"
    description = "Detects abnormal GPS/map config keys or injected JavaScript"
    severity    = "medium"
  strings:
    $json1    = /"routeOverride"\s*:\s*true/ ascii
    $json2    = /"allowRemoteDebug"\s*:\s*true/ ascii
    $js_snip  = "<script>" ascii
  condition:
    any of ($json*) or $js_snip
}

rule AV_CANDiagnostics_Abuse {
  meta:
    author      = "Alexander"
    description = "Detects suspicious shell commands embedded in CAN diagnostic dumps"
    severity    = "medium"
  strings:
    $cmd1 = "system(" ascii
    $cmd2 = "popen(" ascii
    $cmd3 = "exec(" ascii
  condition:
    2 of ($cmd*)
}

rule AV_OTA_ExternalFetch {
  meta:
    author      = "Alexander"
    description = "Detects OTA manifests that pull code from external domains"
    severity    = "high"
  strings:
    $url       = /https?:\/\/[\w\.\-]+\/(updates|firmware)\ // ascii
    $fetch_cmd = /wget\s+https?:\/\ // ascii
  condition:
    $url or $fetch_cmd
}

rule AV_HighLevel_File_Access {
  meta:
    author      = "Alexander"
    description = "Detects attempts to read or write critical system files"
    severity    = "high"
  strings:
    $f1 = "/etc/passwd" ascii
    $f2 = "/etc/shadow" ascii
    $f3 = "/dev/mem" ascii
    $f4 = "/proc/kallsyms" ascii
  condition:
    any of ($f*)
}

rule AV_Command_Injection {
  meta:
    author      = "Alexander"
    description = "Detects suspicious shell injection patterns in scripts"
    severity    = "medium"
  strings:
    $i1 = /;\s*\/bin\/sh/ ascii
    $i2 = /\|\|\s*\/bin\/bash/ ascii
    $i3 = /&&\s*chmod/ ascii
    $i4 = /`shutdown\s+-h\s+now`/ ascii
  condition:
    any of ($i*)
}

rule AV_CAN_Exfiltration {
  meta:
    author      = "Alexander"
    description = "Raw CAN-bus dump with HTTP POST or base64 content"
    severity    = "medium"
  strings:
    $post = "POST /upload" nocase
    $b64  = /[A-Za-z0-9+\/]{20,100}={0,2}/
  condition:
    $post or $b64
}
