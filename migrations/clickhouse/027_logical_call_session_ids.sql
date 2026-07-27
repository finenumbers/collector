ALTER TABLE collector.custom_antifraud_calls
    ADD COLUMN IF NOT EXISTS acct_session_ids Array(String) DEFAULT []
