rule DetectWritableFstab {
    strings:
        $rw_option = /\\s+rw[\\s,]/       // "rw"가 공백 또는 쉼표로 구분된 경우
        $write_option = /\\s+writable[\\s,]/ // "writable"이 포함된 경우
    condition:
        any of them
}
