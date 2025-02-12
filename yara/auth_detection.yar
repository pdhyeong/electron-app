rule DetectionInfo {
    strings:
        $aws_access_key = /AKIA[0-9A-Z]{16}/
        $aws_secret_key = /[A-Za-z0-9/+=]{40}/
        $ssh_private_key = "-----BEGIN RSA PRIVATE KEY-----"
        $generic_token = /[A-Za-z0-9_-]{20,40}/
    conditions:
        $aws_access_key or $aws_secret_key or $ssh_private_key or $generic_token
}

