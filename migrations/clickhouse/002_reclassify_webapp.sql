ALTER TABLE collector.raw_syslog
UPDATE
    header_format = 'rfc3164',
    parser_version = 'smg-3.410-v2',
    parse_status = 'parsed',
    category = 'system_journal',
    component = extract(payload, '(?i)(WEBS|SEC):\\s'),
    message = replaceRegexpOne(
        payload,
        '(?i)^(?:<[0-9]{1,3}>)?[A-Z][a-z]{2}\\s+[0-9]{1,2}\\s+[0-9]{2}:[0-9]{2}:[0-9]{2}\\s+(?:\\S+\\s+)?webapp\\[[0-9]+\\]:\\s+(?:WEBS|SEC):\\s*',
        ''
    ),
    attributes = mapConcat(
        attributes,
        map(
            'application', 'webapp',
            'process_id', extract(payload, '(?i)webapp\\[([0-9]+)\\]')
        )
    )
WHERE category = 'unknown'
  AND match(
      payload,
      '(?i)^(?:<[0-9]{1,3}>)?[A-Z][a-z]{2}\\s+[0-9]{1,2}\\s+[0-9]{2}:[0-9]{2}:[0-9]{2}\\s+(?:\\S+\\s+)?webapp\\[[0-9]+\\]:\\s+(WEBS|SEC):'
  )
SETTINGS mutations_sync = 1;
