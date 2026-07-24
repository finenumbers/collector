ALTER TABLE collector.raw_syslog
UPDATE
    header_format = 'eltex-trace',
    parser_version = 'smg-3.410-v3',
    parse_status = 'parsed',
    category = multiIf(
        match(payload, '(?i)RADIUS|ANTIFRAUD|ACCS-REQUEST|ACCT-SESSION-ID|CALLING-STATION-ID|CALLED-STATION-ID|XPGK-|CISCO-AVPAIR|ELTEX-AVPAIR|H323-(CONF-ID|CREDIT-TIME|CALL-ORIGIN|CALL-TYPE)|NAS-PORT-(ID|TYPE)|FRAMED-IP-ADDRESS|USER-NAME|PASSWORD|\\]\\s+RC:'), 'radius',
        match(payload, '(?i)SS7|ISUP|IAM-|RLC-'), 'isup',
        match(payload, '(?i)\\bSIP|PBXIPC-SIP|CALL-ID'), 'sip',
        match(payload, '(?i)IP-CONN|\\bRTP|\\bRTCP|CONN\\['), 'ip_connections',
        match(payload, '(?i)SM-VP|\\bMSP'), 'ip_modules',
        match(payload, '(?i)ALARM'), 'alarms',
        match(payload, '\\[C[A-Za-z0-9_-]+\\]'), 'call_trace',
        'unknown'
    ),
    component = multiIf(
        match(payload, '(?i)RADIUS|ANTIFRAUD|ACCS-REQUEST|ACCT-SESSION-ID|XPGK-'), 'RADIUS',
        match(payload, '(?i)SS7/ISUP|\\bISUP'), 'SS7/ISUP',
        match(payload, '(?i)PBXIPC-SIP'), 'PBXIPC-SIP',
        match(payload, '(?i)\\bSIP'), 'SIP',
        match(payload, '(?i)CONN\\[|IP-CONN'), 'IP connection',
        component
    ),
    message = replaceRegexpOne(
        payload,
        '(?i)^<[0-9]{1,3}>\\s*<[^>]+>\\s*[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,6})?\\s+\\[[A-Z ]+\\]\\s*(?:\\[[A-Za-z0-9_-]+\\]\\s*)?',
        ''
    ),
    attributes = mapConcat(
        attributes,
        map(
            'hostname', extract(payload, '^<[0-9]{1,3}>\\s*<([^>]+)>'),
            'call_context', extract(payload, '\\[([C][A-Za-z0-9_-]+)\\]')
        )
    )
WHERE (category = 'unknown' OR parse_status != 'parsed')
  AND match(
      payload,
      '^<[0-9]{1,3}>\\s*<[^>]+>\\s*[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,6})?\\s+\\[[A-Z ]+\\]'
  );
