-- Canonical device firmware schemes used by Collector CDR profiles.
UPDATE devices SET firmware='3.410' WHERE firmware LIKE '3.410%';
UPDATE devices SET firmware='3.23.2' WHERE firmware IS DISTINCT FROM '3.410' AND firmware IS DISTINCT FROM '3.23.2';
