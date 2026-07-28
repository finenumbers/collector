package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
)

type AuditLogEntry struct {
	ID           int64           `json:"id"`
	OccurredAt   time.Time       `json:"occurredAt"`
	ActorID      *uuid.UUID      `json:"actorId,omitempty"`
	ActorName    string          `json:"actorName,omitempty"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resourceType"`
	ResourceID   string          `json:"resourceId,omitempty"`
	RemoteIP     string          `json:"remoteIp,omitempty"`
	Details      json.RawMessage `json:"details"`
	Category     string          `json:"category"`
}

func AuditCategory(resourceType, action string) string {
	switch strings.ToLower(resourceType) {
	case "user", "session":
		return "users"
	case "device":
		return "devices"
	case "retention":
		return "retention"
	case "export", "export_job":
		return "exports"
	case "runtime_settings", "system":
		return "system"
	default:
		if strings.Contains(strings.ToLower(action), "login") ||
			strings.Contains(strings.ToLower(action), "logout") {
			return "auth"
		}
		return "other"
	}
}

func (s *Store) ListAuditLogs(
	ctx context.Context, query string, limit int,
) ([]AuditLogEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	query = strings.TrimSpace(query)
	rows, err := s.DB.Query(ctx, `SELECT log.id,log.occurred_at,log.actor_id,
		COALESCE(users.username,''),log.action,log.resource_type,COALESCE(log.resource_id,''),
		COALESCE(host(log.remote_ip),''),log.details
		FROM audit_log log
		LEFT JOIN users ON users.id=log.actor_id
		WHERE ($1='' OR log.action ILIKE '%'||$1||'%'
			OR log.resource_type ILIKE '%'||$1||'%'
			OR COALESCE(log.resource_id,'') ILIKE '%'||$1||'%'
			OR COALESCE(users.username,'') ILIKE '%'||$1||'%'
			OR log.details::text ILIKE '%'||$1||'%')
		ORDER BY log.occurred_at DESC, log.id DESC
		LIMIT $2`, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]AuditLogEntry, 0)
	for rows.Next() {
		var item AuditLogEntry
		var details []byte
		if err := rows.Scan(
			&item.ID, &item.OccurredAt, &item.ActorID, &item.ActorName, &item.Action,
			&item.ResourceType, &item.ResourceID, &item.RemoteIP, &details,
		); err != nil {
			return nil, err
		}
		if len(details) == 0 {
			details = []byte("{}")
		}
		item.Details = details
		item.Category = AuditCategory(item.ResourceType, item.Action)
		items = append(items, item)
	}
	return items, rows.Err()
}
