rule urgent_phish {
    strings:
        $s1 = "urgent" nocase
        $s2 = "account suspended" nocase
        $s3 = "action required" nocase
        $s4 = "verify your identity" nocase
    condition:
        any of them
}

rule malicious_link_patterns {
    strings:
        $p1 = "bit.ly/" nocase
        $p2 = "t.co/" nocase
        $p3 = "tinyurl.com/" nocase
        $p4 = "click here" nocase
    condition:
        any of them
}

rule suspicious_sender {
    strings:
        $r1 = "no-reply" nocase
        $r2 = "admin@" nocase
        $r3 = "security@" nocase
    condition:
        any of them
}
