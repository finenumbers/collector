ALTER TABLE collector.satel_rtu_cdr
    ADD COLUMN IF NOT EXISTS remote_src_geoip_iso String DEFAULT '' AFTER remote_dst_sig_address,
    ADD COLUMN IF NOT EXISTS remote_src_geoip_city String DEFAULT '' AFTER remote_src_geoip_iso,
    ADD COLUMN IF NOT EXISTS remote_src_asn_org String DEFAULT '' AFTER remote_src_geoip_city,
    ADD COLUMN IF NOT EXISTS remote_dst_geoip_iso String DEFAULT '' AFTER remote_src_asn_org,
    ADD COLUMN IF NOT EXISTS remote_dst_geoip_city String DEFAULT '' AFTER remote_dst_geoip_iso,
    ADD COLUMN IF NOT EXISTS remote_dst_asn_org String DEFAULT '' AFTER remote_dst_geoip_city;
