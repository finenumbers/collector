package analytics

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

const SyslogGroupingVersion = "readable-syslog-v1"

var ErrSyslogConstructNotFound = errors.New("syslog construct not found")

type SyslogConstruct struct {
	DeviceID         uuid.UUID         `json:"deviceId"`
	TimezoneRevision uint64            `json:"timezoneRevision"`
	GroupingVersion  string            `json:"groupingVersion"`
	ConstructID      uuid.UUID         `json:"constructId"`
	UpdatedAt        time.Time         `json:"updatedAt"`
	StartedAt        time.Time         `json:"startedAt"`
	EndedAt          time.Time         `json:"endedAt"`
	ConstructType    string            `json:"constructType"`
	Category         string            `json:"category"`
	Direction        string            `json:"direction"`
	Title            string            `json:"title"`
	Summary          string            `json:"summary"`
	CallContext      string            `json:"callContext"`
	MessageName      string            `json:"messageName"`
	Completeness     string            `json:"completeness"`
	GroupingMethod   string            `json:"groupingMethod"`
	GroupingReason   string            `json:"groupingReason"`
	Confidence       float32           `json:"confidence"`
	MemberCount      uint32            `json:"memberCount"`
	HiddenCount      uint32            `json:"hiddenCount"`
	SearchableText   string            `json:"searchableText"`
	Attributes       map[string]string `json:"attributes"`
}

type SyslogConstructMember struct {
	DeviceID         uuid.UUID `json:"deviceId"`
	TimezoneRevision uint64    `json:"timezoneRevision"`
	GroupingVersion  string    `json:"groupingVersion"`
	ConstructID      uuid.UUID `json:"constructId"`
	EventID          uuid.UUID `json:"eventId"`
	Ordinal          uint32    `json:"ordinal"`
	Role             string    `json:"role"`
	Technical        bool      `json:"technical"`
	LinkedAt         time.Time `json:"linkedAt"`
}

type SyslogFragmentLink struct {
	DeviceID         uuid.UUID `json:"deviceId"`
	TimezoneRevision uint64    `json:"timezoneRevision"`
	GroupingVersion  string    `json:"groupingVersion"`
	ChildEventID     uuid.UUID `json:"childEventId"`
	ParentEventID    uuid.UUID `json:"parentEventId"`
	LinkMethod       string    `json:"linkMethod"`
	FragmentKind     string    `json:"fragmentKind"`
	Confidence       float32   `json:"confidence"`
	LinkedAt         time.Time `json:"linkedAt"`
}

type SyslogConstructCursor struct {
	StartedAt   time.Time `json:"before"`
	ConstructID uuid.UUID `json:"beforeId"`
}

type SyslogConstructPage struct {
	Items      []SyslogConstruct      `json:"items"`
	HasMore    bool                   `json:"hasMore"`
	NextCursor *SyslogConstructCursor `json:"nextCursor"`
}

type SyslogConstructDetail struct {
	Construct SyslogConstruct `json:"construct"`
	Members   []EventRow      `json:"members"`
}

type SyslogConstructFilters struct {
	Category     string
	Search       string
	Kind         string
	Direction    string
	MessageName  string
	CallContext  string
	ProblemsOnly bool
}

func (c *Client) InsertSyslogConstructsBatch(
	ctx context.Context, constructs []SyslogConstruct,
) error {
	if len(constructs) == 0 {
		return nil
	}
	batch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.syslog_constructs
		(device_id,timezone_revision,grouping_version,construct_id,updated_at,started_at,
		 ended_at,construct_type,category,direction,title,summary,call_context,message_name,
		 completeness,grouping_method,grouping_reason,confidence,member_count,hidden_count,
		 searchable_text,attributes)`)
	if err != nil {
		return err
	}
	for _, item := range constructs {
		if item.GroupingVersion == "" {
			item.GroupingVersion = SyslogGroupingVersion
		}
		if err := batch.Append(
			item.DeviceID, item.TimezoneRevision, item.GroupingVersion, item.ConstructID,
			item.UpdatedAt, item.StartedAt, item.EndedAt, item.ConstructType, item.Category,
			item.Direction, item.Title, item.Summary, item.CallContext, item.MessageName,
			item.Completeness, item.GroupingMethod, item.GroupingReason, item.Confidence,
			item.MemberCount, item.HiddenCount, item.SearchableText, item.Attributes,
		); err != nil {
			return err
		}
	}
	return batch.Send()
}

func (c *Client) InsertSyslogConstructMembersBatch(
	ctx context.Context, members []SyslogConstructMember,
) error {
	if len(members) == 0 {
		return nil
	}
	batch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.syslog_construct_members
		(device_id,timezone_revision,grouping_version,construct_id,event_id,ordinal,role,
		 technical,linked_at)`)
	if err != nil {
		return err
	}
	for _, item := range members {
		if item.GroupingVersion == "" {
			item.GroupingVersion = SyslogGroupingVersion
		}
		if err := batch.Append(
			item.DeviceID, item.TimezoneRevision, item.GroupingVersion, item.ConstructID,
			item.EventID, item.Ordinal, item.Role, boolToUInt8(item.Technical), item.LinkedAt,
		); err != nil {
			return err
		}
	}
	return batch.Send()
}

func (c *Client) InsertSyslogFragmentLinksBatch(
	ctx context.Context, links []SyslogFragmentLink,
) error {
	if len(links) == 0 {
		return nil
	}
	batch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.syslog_fragment_links
		(device_id,timezone_revision,grouping_version,child_event_id,parent_event_id,
		 link_method,fragment_kind,confidence,linked_at)`)
	if err != nil {
		return err
	}
	for _, item := range links {
		if item.GroupingVersion == "" {
			item.GroupingVersion = SyslogGroupingVersion
		}
		if err := batch.Append(
			item.DeviceID, item.TimezoneRevision, item.GroupingVersion, item.ChildEventID,
			item.ParentEventID, item.LinkMethod, item.FragmentKind, item.Confidence,
			item.LinkedAt,
		); err != nil {
			return err
		}
	}
	return batch.Send()
}

func (c *Client) ListSyslogConstructsPage(
	ctx context.Context,
	deviceID uuid.UUID,
	category string,
	search string,
	limit uint64,
	cursor *SyslogConstructCursor,
) (SyslogConstructPage, error) {
	return c.ListSyslogConstructsFilteredPage(ctx, deviceID, SyslogConstructFilters{
		Category: category, Search: search,
	}, limit, cursor)
}

func (c *Client) ListSyslogConstructsFilteredPage(
	ctx context.Context,
	deviceID uuid.UUID,
	filters SyslogConstructFilters,
	limit uint64,
	cursor *SyslogConstructCursor,
) (SyslogConstructPage, error) {
	if limit == 0 || limit > 50000 {
		limit = 200
	}
	revision, err := c.ActiveDeviceRevision(ctx, deviceID)
	if err != nil {
		return SyslogConstructPage{}, err
	}
	if revision == 0 {
		return SyslogConstructPage{Items: []SyslogConstruct{}}, nil
	}
	query := `SELECT device_id,timezone_revision,grouping_version,construct_id,updated_at,
		started_at,ended_at,construct_type,category,direction,title,summary,call_context,
		message_name,completeness,grouping_method,grouping_reason,confidence,member_count,
		hidden_count,searchable_text,attributes
		FROM collector.syslog_constructs FINAL
		WHERE device_id=? AND timezone_revision=? AND grouping_version=?`
	args := []any{deviceID, revision, SyslogGroupingVersion}
	if filters.Category != "" && filters.Category != "all" {
		query += ` AND category=?`
		args = append(args, filters.Category)
	}
	if filters.Search != "" {
		query += ` AND (positionCaseInsensitive(title,?)>0
			OR positionCaseInsensitive(summary,?)>0
			OR positionCaseInsensitive(searchable_text,?)>0)`
		args = append(args, filters.Search, filters.Search, filters.Search)
	}
	if filters.Kind != "" {
		query += ` AND construct_type=?`
		args = append(args, filters.Kind)
	}
	if filters.Direction != "" {
		query += ` AND direction=?`
		args = append(args, filters.Direction)
	}
	if filters.MessageName != "" {
		query += ` AND positionCaseInsensitive(message_name,?)>0`
		args = append(args, filters.MessageName)
	}
	if filters.CallContext != "" {
		query += ` AND positionCaseInsensitive(call_context,?)>0`
		args = append(args, filters.CallContext)
	}
	if filters.ProblemsOnly {
		query += ` AND (completeness!='complete' OR category IN ('alarms','unknown')
			OR attributes['q850_cause'] NOT IN ('','16'))`
	}
	if cursor != nil {
		query += ` AND (started_at<? OR (started_at=? AND construct_id<?))`
		args = append(args, cursor.StartedAt, cursor.StartedAt, cursor.ConstructID)
	}
	query += ` ORDER BY started_at DESC,construct_id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := c.Conn.Query(ctx, query, args...)
	if err != nil {
		return SyslogConstructPage{}, err
	}
	defer rows.Close()
	items := make([]SyslogConstruct, 0, limit+1)
	for rows.Next() {
		var item SyslogConstruct
		if err := scanSyslogConstruct(rows.Scan, &item); err != nil {
			return SyslogConstructPage{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return SyslogConstructPage{}, err
	}
	hasMore := uint64(len(items)) > limit
	if hasMore {
		items = items[:limit]
	}
	page := SyslogConstructPage{Items: items, HasMore: hasMore}
	if hasMore && len(items) > 0 {
		last := items[len(items)-1]
		page.NextCursor = &SyslogConstructCursor{
			StartedAt: last.StartedAt, ConstructID: last.ConstructID,
		}
	}
	return page, nil
}

func (c *Client) GetSyslogConstruct(
	ctx context.Context, deviceID, constructID uuid.UUID,
) (SyslogConstructDetail, error) {
	revision, err := c.ActiveDeviceRevision(ctx, deviceID)
	if err != nil {
		return SyslogConstructDetail{}, err
	}
	if revision == 0 {
		return SyslogConstructDetail{}, ErrSyslogConstructNotFound
	}
	var construct SyslogConstruct
	row := c.Conn.QueryRow(ctx, `SELECT device_id,timezone_revision,grouping_version,
		construct_id,updated_at,started_at,ended_at,construct_type,category,direction,title,
		summary,call_context,message_name,completeness,grouping_method,grouping_reason,
		confidence,member_count,hidden_count,searchable_text,attributes
		FROM collector.syslog_constructs FINAL
		WHERE device_id=? AND timezone_revision=? AND grouping_version=? AND construct_id=?
		ORDER BY updated_at DESC LIMIT 1`,
		deviceID, revision, SyslogGroupingVersion, constructID)
	if err := scanSyslogConstruct(row.Scan, &construct); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SyslogConstructDetail{}, ErrSyslogConstructNotFound
		}
		return SyslogConstructDetail{}, err
	}
	timezone, err := c.deviceRevisionTimezone(ctx, deviceID, revision)
	if err != nil {
		return SyslogConstructDetail{}, err
	}
	rows, err := c.Conn.Query(ctx, `WITH facts AS
		(
			SELECT event_id,argMax(received_at,interpreted_at) AS received_at,
				argMax(event_time_utc,interpreted_at) AS event_time,
				argMax(category,interpreted_at) AS category,
				argMax(component,interpreted_at) AS component,
				argMax(message,interpreted_at) AS message,
				argMax(parse_status,interpreted_at) AS parse_status,
				argMax(attributes,interpreted_at) AS attributes,
				argMax(source_timezone,interpreted_at) AS source_timezone
			FROM collector.syslog_facts
			WHERE device_id=? AND timezone_revision=?
			GROUP BY event_id
		),
		raw AS
		(
			SELECT event_id,any(payload) AS payload
			FROM collector.raw_syslog
			WHERE device_id=?
			GROUP BY event_id
		)
		SELECT f.event_id,f.received_at,f.event_time,f.category,f.component,f.message,
			r.payload,f.parse_status,f.attributes,f.source_timezone
		FROM collector.syslog_construct_members AS m FINAL
		INNER JOIN facts AS f ON f.event_id=m.event_id
		INNER JOIN raw AS r ON r.event_id=m.event_id
		WHERE m.device_id=? AND m.timezone_revision=? AND m.grouping_version=?
			AND m.construct_id=?
		ORDER BY m.ordinal,m.event_id`,
		deviceID, revision, deviceID, deviceID, revision, SyslogGroupingVersion, constructID)
	if err != nil {
		return SyslogConstructDetail{}, err
	}
	defer rows.Close()
	members := make([]EventRow, 0, construct.MemberCount)
	for rows.Next() {
		var item EventRow
		if err := rows.Scan(
			&item.EventID, &item.ReceivedAt, &item.EventTime, &item.Category,
			&item.Component, &item.Message, &item.RawPayload, &item.Status,
			&item.Attributes, &item.SourceTimezone,
		); err != nil {
			return SyslogConstructDetail{}, err
		}
		item.EventTimeLocal = localRFC3339(item.EventTime, timezone)
		item.ReceivedAtLocal = localRFC3339(&item.ReceivedAt, timezone)
		members = append(members, item)
	}
	if err := rows.Err(); err != nil {
		return SyslogConstructDetail{}, err
	}
	return SyslogConstructDetail{Construct: construct, Members: members}, nil
}

type scanFunction func(dest ...any) error

func scanSyslogConstruct(scan scanFunction, item *SyslogConstruct) error {
	return scan(
		&item.DeviceID, &item.TimezoneRevision, &item.GroupingVersion,
		&item.ConstructID, &item.UpdatedAt, &item.StartedAt, &item.EndedAt,
		&item.ConstructType, &item.Category, &item.Direction, &item.Title,
		&item.Summary, &item.CallContext, &item.MessageName, &item.Completeness,
		&item.GroupingMethod, &item.GroupingReason, &item.Confidence,
		&item.MemberCount, &item.HiddenCount, &item.SearchableText, &item.Attributes,
	)
}
