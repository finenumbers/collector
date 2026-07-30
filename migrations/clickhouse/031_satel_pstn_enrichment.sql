ALTER TABLE collector.satel_rtu_cdr
    ADD COLUMN IF NOT EXISTS bill_ani_operator String DEFAULT '' AFTER bill_dnis,
    ADD COLUMN IF NOT EXISTS bill_dnis_operator String DEFAULT '' AFTER bill_ani_operator,
    ADD COLUMN IF NOT EXISTS bill_ani_region String DEFAULT '' AFTER bill_dnis_operator,
    ADD COLUMN IF NOT EXISTS bill_dnis_region String DEFAULT '' AFTER bill_ani_region;
