package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type IngestRetryDisposition struct {
	Retry       bool
	RemoveLocal bool
}

func IngestFileRetryDisposition(status string, sameParserConfig bool) IngestRetryDisposition {
	switch status {
	case "processed", "archived":
		return IngestRetryDisposition{RemoveLocal: true}
	case "quarantined":
		return IngestRetryDisposition{Retry: !sameParserConfig}
	default:
		return IngestRetryDisposition{Retry: true}
	}
}

// ClaimIngestFileForParser consults parser provenance when reopening an
// immutable local file. A quarantine is terminal while the content and parser
// configuration are unchanged, but becomes eligible after a parser/device
// configuration change. Failed infrastructure work remains retryable.
func (s *Store) ClaimIngestFileForParser(
	ctx context.Context,
	deviceID uuid.UUID,
	name, objectKey, checksum string,
	size int64,
	parserTemplate, parserIdentity string,
) (IngestFileClaim, error) {
	var claim IngestFileClaim
	var storedTemplate, storedIdentity string
	err := s.DB.QueryRow(ctx, `INSERT INTO ingest_files(
			device_id,original_name,object_key,sha256,size_bytes,status,
			parser_template,parser_version
		)
		VALUES($1,$2,$3,$4,$5,'received',$6,$7)
		ON CONFLICT(device_id,sha256) DO NOTHING
		RETURNING id,object_key,status,rows_valid,parser_template,parser_version`,
		deviceID, name, objectKey, checksum, size, parserTemplate, parserIdentity,
	).Scan(
		&claim.ID, &claim.ObjectKey, &claim.Status, &claim.RowsValid,
		&storedTemplate, &storedIdentity,
	)
	if err == nil {
		claim.Retry = true
		return claim, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return IngestFileClaim{}, err
	}

	err = s.DB.QueryRow(ctx, `SELECT id,object_key,status,rows_valid,
			parser_template,parser_version
		FROM ingest_files WHERE device_id=$1 AND sha256=$2`, deviceID, checksum).
		Scan(
			&claim.ID, &claim.ObjectKey, &claim.Status, &claim.RowsValid,
			&storedTemplate, &storedIdentity,
		)
	if errors.Is(err, pgx.ErrNoRows) {
		return IngestFileClaim{}, ErrNotFound
	}
	if err != nil {
		return IngestFileClaim{}, err
	}

	sameParser := storedTemplate == parserTemplate && storedIdentity == parserIdentity
	disposition := IngestFileRetryDisposition(claim.Status, sameParser)
	if !disposition.Retry {
		claim.RemoveLocal = disposition.RemoveLocal
		return claim, nil
	}

	_, err = s.DB.Exec(ctx, `UPDATE ingest_files
		SET original_name=$2,object_key=$3,size_bytes=$4,status='received',
			error=NULL,processed_at=NULL,rows_total=0,rows_valid=0,
			parser_template=$5,parser_version=$6
		WHERE id=$1`,
		claim.ID, name, objectKey, size, parserTemplate, parserIdentity,
	)
	if err != nil {
		return IngestFileClaim{}, err
	}
	claim.ObjectKey = objectKey
	claim.Status = "received"
	claim.RowsValid = 0
	claim.Retry = true
	return claim, nil
}
