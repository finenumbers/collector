ALTER TABLE collector.raw_syslog
UPDATE
    header_format = multiIf(
        match(payload, '(?i)^<[0-9]{1,3}>\\s*<[^>]+>\\s*[0-9]{2}:[0-9]{2}:[0-9]{2}'), 'eltex-trace',
        match(payload, '(?i)^(?:<[0-9]{1,3}>)?[A-Z][a-z]{2}\\s+[0-9]{1,2}\\s+[0-9]{2}:[0-9]{2}:[0-9]{2}'), 'rfc3164',
        header_format
    ),
    parser_version = 'smg-3.410-v4',
    parse_status = 'parsed',
    category = multiIf(
        match(payload, '(?i)(?:webapp|webspp)(?:\\[[0-9]+\\])?:\\s*(?:WEBS|SEC)\\s*:') OR
            match(payload, '(?i)^(?:<[0-9]{1,3}>)?[A-Z][a-z]{2}\\s+[0-9]{1,2}\\s+[0-9]{2}:[0-9]{2}:[0-9]{2}\\s+(?:WEBS|SEC)\\s*:'), 'system_journal',
        match(payload, '(?i)RADIUS|ANTIFRAUD|ACCS-REQUEST|ACCESS-(REQUEST|ACCEPT|REJECT)|ACCOUNTING-(REQUEST|RESPONSE)|ACCT-SESSION-ID|CALLING-STATION-ID|CALLED-STATION-ID|XPGK-|CISCO-AVPAIR|ELTEX-AVPAIR|H323-(CONF-ID|CREDIT-TIME|CALL-ORIGIN|CALL-TYPE)|NAS-PORT-(ID|TYPE)|FRAMED-IP-ADDRESS|USER-NAME|PASSWORD|\\]\\s+RC\\s*:'), 'radius',
        match(payload, '(?i)SS7|ISUP|IAM-|RLC-'), 'isup',
        match(payload, '(?i)Q\\.931|Q931|DSS1'), 'q931',
        match(payload, '(?i)\\bSIP|PBXIPC-SIP|INVITE|CALL-ID'), 'sip',
        match(payload, '(?i)IP-CONN|\\bRTP|\\bRTCP|CONN\\['), 'ip_connections',
        match(payload, '(?i)SM-VP|\\bMSP'), 'ip_modules',
        match(payload, '(?i)(?:^|[\\s:;,])ALARMS?(?:$|[\\s:;,])|АВАР'), 'alarms',
        match(payload, '(?i)CONFIG|COMMAND|USERLOG'), 'config_history',
        match(payload, '(?i)AUTH|LOGIN|LOGOUT'), 'system_journal',
        match(payload, '\\[C[A-Za-z0-9_-]+\\]') OR match(payload, '(?i)(?:^|[\\s:;,])CALL(?:$|[\\s:;,])|(?:^|[\\s:;,])PORT\\s+[0-9]'), 'call_trace',
        match(payload, '(?i)^(?:<[0-9]{1,3}>)?[A-Z][a-z]{2}\\s+[0-9]{1,2}\\s+[0-9]{2}:[0-9]{2}:[0-9]{2}\\s+(?:\\S+\\s+)?[A-Za-z0-9_.-]+(?:\\[[0-9]+\\])?:'), 'system_journal',
        'unknown'
    ),
    component = multiIf(
        match(payload, '(?i)(?:webapp|webspp)(?:\\[[0-9]+\\])?:\\s*(WEBS|SEC)\\s*:'), extract(payload, '(?i)(?:webapp|webspp)(?:\\[[0-9]+\\])?:\\s*(WEBS|SEC)\\s*:'),
        match(payload, '(?i)RADIUS|ANTIFRAUD|ACCS-REQUEST|ACCT-SESSION-ID|XPGK-'), 'RADIUS',
        match(payload, '(?i)SS7/ISUP|\\bISUP'), 'SS7/ISUP',
        match(payload, '(?i)Q\\.931|Q931|DSS1'), 'Q.931',
        match(payload, '(?i)PBXIPC-SIP'), 'PBXIPC-SIP',
        match(payload, '(?i)\\bSIP'), 'SIP',
        match(payload, '(?i)CONN\\[|IP-CONN'), 'IP connection',
        component
    ),
    message = multiIf(
        match(payload, '(?i)(?:webapp|webspp)(?:\\[[0-9]+\\])?:\\s*(?:WEBS|SEC)\\s*:'),
            replaceRegexpOne(payload, '(?i)^(?:<[0-9]{1,3}>)?[A-Z][a-z]{2}\\s+[0-9]{1,2}\\s+[0-9]{2}:[0-9]{2}:[0-9]{2}\\s+(?:\\S+\\s+)?(?:webapp|webspp)(?:\\[[0-9]+\\])?:\\s*(?:WEBS|SEC)\\s*:\\s*', ''),
        match(payload, '(?i)^<[0-9]{1,3}>\\s*<[^>]+>\\s*[0-9]{2}:[0-9]{2}:[0-9]{2}'),
            replaceRegexpOne(payload, '(?i)^<[0-9]{1,3}>\\s*<[^>]+>\\s*[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,6})?\\s+(?:\\[[A-Z][A-Z0-9 _-]*\\]\\s*)?(?:\\[[A-Za-z0-9_-]+\\]\\s*)?', ''),
        message
    ),
    attributes = mapConcat(
        attributes,
        map(
            'application', extract(payload, '(?i)(webapp|webspp)(?:\\[[0-9]+\\])?:'),
            'process_id', extract(payload, '(?i)(?:webapp|webspp)\\[([0-9]+)\\]'),
            'hostname', extract(payload, '^<[0-9]{1,3}>\\s*<([^>]+)>'),
            'call_context', extract(payload, '\\[(C[A-Za-z0-9_-]+)\\]')
        )
    )
WHERE match(
    payload,
    '(?i)^<[0-9]{1,3}>\\s*<[^>]+>\\s*[0-9]{2}:[0-9]{2}:[0-9]{2}|^(?:<[0-9]{1,3}>)?[A-Z][a-z]{2}\\s+[0-9]{1,2}\\s+[0-9]{2}:[0-9]{2}:[0-9]{2}'
)
SETTINGS mutations_sync = 1;
