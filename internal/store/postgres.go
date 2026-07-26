package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/argon2"
)

var (
	ErrNotFound       = errors.New("not found")
	ErrDeviceDeleting = errors.New("device is being deleted")
)

type Store struct {
	DB                  *pgxpool.Pool
	deviceCacheRevision atomic.Uint64
	deviceLocks         sync.Map
}

type User struct {
	ID       uuid.UUID `json:"id"`
	Username string    `json:"username"`
	Role     string    `json:"role"`
}

type ManagedUser struct {
	ID             uuid.UUID  `json:"id"`
	Username       string     `json:"username"`
	Role           string     `json:"role"`
	Active         bool       `json:"active"`
	CreatedAt      time.Time  `json:"createdAt"`
	LastSeenAt     *time.Time `json:"lastSeenAt"`
	LockedUntil    *time.Time `json:"lockedUntil"`
	FailedAttempts int        `json:"failedAttempts"`
}

type UserUpdate struct {
	Role     string `json:"role"`
	Active   bool   `json:"active"`
	Password string `json:"password"`
}

type Device struct {
	ID                     uuid.UUID       `json:"id"`
	Name                   string          `json:"name"`
	Model                  string          `json:"model"`
	Firmware               string          `json:"firmware"`
	Timezone               string          `json:"timezone"`
	ActiveTimezone         string          `json:"activeTimezone"`
	TimezoneRevision       int64           `json:"timezoneRevision"`
	ActiveTimezoneRevision int64           `json:"activeTimezoneRevision"`
	CDRSourceTimezone      string          `json:"cdrSourceTimezone"`
	ManagementIP           *string         `json:"managementIp,omitempty"`
	SyslogSourceIP         string          `json:"syslogSourceIp"`
	DeviceSign             string          `json:"deviceSign"`
	AntifraudEnabled       bool            `json:"antifraudEnabled"`
	AntifraudMode          string          `json:"antifraudMode"`
	FTPUsername            string          `json:"ftpUsername"`
	FTPHome                string          `json:"ftpHome"`
	CDRColumns             json.RawMessage `json:"cdrColumns"`
	Enabled                bool            `json:"enabled"`
	PurgeState             string          `json:"purgeState"`
	PurgeError             string          `json:"purgeError,omitempty"`
	CreatedAt              time.Time       `json:"createdAt"`
	GeneratedPassword      string          `json:"generatedPassword,omitempty"`
}

type DeviceTimeConfig struct {
	ActiveTimezone         string `json:"activeTimezone"`
	ActiveTimezoneRevision int64  `json:"activeTimezoneRevision"`
	Timezone               string `json:"timezone"`
	TimezoneRevision       int64  `json:"timezoneRevision"`
}

type NewDevice struct {
	Name             string   `json:"name"`
	Model            string   `json:"model"`
	Firmware         string   `json:"firmware"`
	Timezone         string   `json:"timezone"`
	ManagementIP     string   `json:"managementIp"`
	SyslogSourceIP   string   `json:"syslogSourceIp"`
	DeviceSign       string   `json:"deviceSign"`
	AntifraudEnabled bool     `json:"antifraudEnabled"`
	AntifraudMode    string   `json:"antifraudMode"`
	CDRColumns       []string `json:"cdrColumns"`
}

type DeviceUpdate struct {
	Name             string   `json:"name"`
	Firmware         string   `json:"firmware"`
	Timezone         string   `json:"timezone"`
	ManagementIP     string   `json:"managementIp"`
	SyslogSourceIP   string   `json:"syslogSourceIp"`
	DeviceSign       string   `json:"deviceSign"`
	AntifraudEnabled bool     `json:"antifraudEnabled"`
	AntifraudMode    string   `json:"antifraudMode"`
	Enabled          bool     `json:"enabled"`
	CDRColumns       []string `json:"cdrColumns"`
}

type Session struct {
	User User
	CSRF string
}

func Open(ctx context.Context, url string) (*Store, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{DB: pool}, nil
}

func (s *Store) Migrate(ctx context.Context, directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		content, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return err
		}
		if _, err := s.DB.Exec(ctx, string(content)); err != nil {
			return fmt.Errorf("%s: %w", entry.Name(), err)
		}
	}
	return nil
}

func (s *Store) IsBootstrapped(ctx context.Context) (bool, error) {
	var exists bool
	err := s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE role='admin' AND active)`).Scan(&exists)
	return exists, err
}

func (s *Store) CreateInitialAdmin(ctx context.Context, username, password string) (User, error) {
	username = strings.TrimSpace(strings.ToLower(username))
	if len(username) < 3 || len(password) < 12 {
		return User{}, errors.New("username must be at least 3 characters and password at least 12")
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1016)`); err != nil {
		return User{}, err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE role='admin')`).Scan(&exists); err != nil {
		return User{}, err
	}
	if exists {
		return User{}, errors.New("initial administrator already exists")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return User{}, err
	}
	var user User
	err = tx.QueryRow(ctx,
		`INSERT INTO users (username,password_hash,role) VALUES ($1,$2,'admin') RETURNING id,username,role`,
		username, hash,
	).Scan(&user.ID, &user.Username, &user.Role)
	if err != nil {
		return User{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_log(action,resource_type,resource_id) VALUES('bootstrap_admin','user',$1)`, user.ID.String()); err != nil {
		return User{}, err
	}
	return user, tx.Commit(ctx)
}

func (s *Store) Authenticate(ctx context.Context, username, password string) (User, error) {
	var user User
	var hash string
	var active bool
	var lockedUntil *time.Time
	err := s.DB.QueryRow(ctx,
		`SELECT id,username,role,password_hash,active,locked_until FROM users WHERE username=$1`,
		strings.ToLower(strings.TrimSpace(username)),
	).Scan(&user.ID, &user.Username, &user.Role, &hash, &active, &lockedUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	if !active || (lockedUntil != nil && lockedUntil.After(time.Now())) || !verifyPassword(password, hash) {
		_, _ = s.DB.Exec(ctx, `UPDATE users SET failed_attempts=failed_attempts+1,
			locked_until=CASE WHEN failed_attempts+1>=5 THEN now()+interval '15 minutes' ELSE locked_until END
			WHERE id=$1`, user.ID)
		return User{}, ErrNotFound
	}
	_, err = s.DB.Exec(ctx, `UPDATE users SET failed_attempts=0,locked_until=NULL WHERE id=$1`, user.ID)
	return user, err
}

func (s *Store) CreateSession(ctx context.Context, user User, ttl time.Duration, userAgent, remoteIP string) (token, csrf string, err error) {
	token, err = randomToken(32)
	if err != nil {
		return "", "", err
	}
	csrf, err = randomToken(24)
	if err != nil {
		return "", "", err
	}
	tokenHash := sha256.Sum256([]byte(token))
	csrfHash := sha256.Sum256([]byte(csrf))
	_, err = s.DB.Exec(ctx, `INSERT INTO sessions(id_hash,user_id,csrf_hash,expires_at,user_agent,remote_ip)
		VALUES($1,$2,$3,$4,$5,$6)`,
		tokenHash[:], user.ID, csrfHash[:], time.Now().Add(ttl), userAgent, nullableIP(remoteIP))
	return token, csrf, err
}

func (s *Store) Session(ctx context.Context, token, csrf string, requireCSRF bool) (Session, error) {
	tokenHash := sha256.Sum256([]byte(token))
	var session Session
	var csrfHash []byte
	err := s.DB.QueryRow(ctx, `SELECT u.id,u.username,u.role,s.csrf_hash
		FROM sessions s JOIN users u ON u.id=s.user_id
		WHERE s.id_hash=$1 AND s.expires_at>now() AND u.active`, tokenHash[:],
	).Scan(&session.User.ID, &session.User.Username, &session.User.Role, &csrfHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, err
	}
	if requireCSRF {
		provided := sha256.Sum256([]byte(csrf))
		if !equalBytes(provided[:], csrfHash) {
			return Session{}, ErrNotFound
		}
	}
	if _, err := s.DB.Exec(ctx, `UPDATE sessions SET last_seen_at=now() WHERE id_hash=$1`, tokenHash[:]); err != nil {
		return Session{}, err
	}
	session.CSRF = csrf
	return session, nil
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	hash := sha256.Sum256([]byte(token))
	_, err := s.DB.Exec(ctx, `DELETE FROM sessions WHERE id_hash=$1`, hash[:])
	return err
}

func (s *Store) ListUsers(ctx context.Context) ([]ManagedUser, error) {
	rows, err := s.DB.Query(ctx, `SELECT u.id,u.username,u.role,u.active,u.created_at,
		max(s.last_seen_at),u.locked_until,u.failed_attempts
		FROM users u LEFT JOIN sessions s ON s.user_id=u.id
		GROUP BY u.id ORDER BY u.username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []ManagedUser
	for rows.Next() {
		var user ManagedUser
		if err := rows.Scan(&user.ID, &user.Username, &user.Role, &user.Active, &user.CreatedAt,
			&user.LastSeenAt, &user.LockedUntil, &user.FailedAttempts); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *Store) ManagedUser(ctx context.Context, id uuid.UUID) (ManagedUser, error) {
	var user ManagedUser
	err := s.DB.QueryRow(ctx, `SELECT u.id,u.username,u.role,u.active,u.created_at,
		max(s.last_seen_at),u.locked_until,u.failed_attempts
		FROM users u LEFT JOIN sessions s ON s.user_id=u.id
		WHERE u.id=$1 GROUP BY u.id`, id).Scan(
		&user.ID, &user.Username, &user.Role, &user.Active, &user.CreatedAt,
		&user.LastSeenAt, &user.LockedUntil, &user.FailedAttempts,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ManagedUser{}, ErrNotFound
	}
	return user, err
}

func (s *Store) CleanupExpiredSessions(ctx context.Context) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM sessions WHERE expires_at<=now()`)
	return err
}

func (s *Store) CreateUser(
	ctx context.Context, username, password, role string, actor User, remoteIP string,
) (ManagedUser, error) {
	username = strings.TrimSpace(username)
	if username == "" || len(password) < 12 || !validRole(role) {
		return ManagedUser{}, errors.New("username, valid role and password of at least 12 characters are required")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return ManagedUser{}, err
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return ManagedUser{}, err
	}
	defer tx.Rollback(ctx)
	var user ManagedUser
	err = tx.QueryRow(ctx, `INSERT INTO users(username,password_hash,role)
		VALUES($1,$2,$3) RETURNING id,username,role,active,created_at`,
		username, hash, role).Scan(&user.ID, &user.Username, &user.Role, &user.Active, &user.CreatedAt)
	if err != nil {
		return ManagedUser{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_log
		(actor_id,action,resource_type,resource_id,remote_ip,details)
		VALUES($1,'user_create','user',$2,$3,$4)`,
		actor.ID, user.ID.String(), nullableIP(remoteIP),
		map[string]string{"username": user.Username, "role": user.Role}); err != nil {
		return ManagedUser{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ManagedUser{}, err
	}
	return s.ManagedUser(ctx, user.ID)
}

func (s *Store) UpdateUser(
	ctx context.Context, id uuid.UUID, input UserUpdate, actor User, remoteIP string,
) (ManagedUser, error) {
	if !validRole(input.Role) {
		return ManagedUser{}, errors.New("invalid role")
	}
	if id == actor.ID && !input.Active {
		return ManagedUser{}, errors.New("cannot deactivate the current user")
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return ManagedUser{}, err
	}
	defer tx.Rollback(ctx)
	var oldRole string
	var oldActive bool
	if err := tx.QueryRow(ctx, `SELECT role,active FROM users WHERE id=$1 FOR UPDATE`, id).
		Scan(&oldRole, &oldActive); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ManagedUser{}, ErrNotFound
		}
		return ManagedUser{}, err
	}
	if oldRole == "admin" && oldActive && (input.Role != "admin" || !input.Active) {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('collector-active-admins'))`); err != nil {
			return ManagedUser{}, err
		}
		var otherAdmins int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM users
			WHERE id<>$1 AND role='admin' AND active`, id).Scan(&otherAdmins); err != nil {
			return ManagedUser{}, err
		}
		if otherAdmins == 0 {
			return ManagedUser{}, errors.New("cannot remove the last active administrator")
		}
	}
	var user ManagedUser
	if input.Password == "" {
		err = tx.QueryRow(ctx, `UPDATE users SET role=$2,active=$3,updated_at=now()
			WHERE id=$1 RETURNING id,username,role,active,created_at`,
			id, input.Role, input.Active).
			Scan(&user.ID, &user.Username, &user.Role, &user.Active, &user.CreatedAt)
	} else {
		if len(input.Password) < 12 {
			return ManagedUser{}, errors.New("password must contain at least 12 characters")
		}
		hash, hashErr := hashPassword(input.Password)
		if hashErr != nil {
			return ManagedUser{}, hashErr
		}
		err = tx.QueryRow(ctx, `UPDATE users
			SET role=$2,active=$3,password_hash=$4,failed_attempts=0,locked_until=NULL,updated_at=now()
			WHERE id=$1 RETURNING id,username,role,active,created_at`,
			id, input.Role, input.Active, hash).
			Scan(&user.ID, &user.Username, &user.Role, &user.Active, &user.CreatedAt)
	}
	if err != nil {
		return ManagedUser{}, err
	}
	if !user.Active || input.Password != "" {
		if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1`, id); err != nil {
			return ManagedUser{}, err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_log
		(actor_id,action,resource_type,resource_id,remote_ip,details)
		VALUES($1,'user_update','user',$2,$3,$4)`,
		actor.ID, id.String(), nullableIP(remoteIP),
		map[string]any{"role": user.Role, "active": user.Active, "passwordChanged": input.Password != ""}); err != nil {
		return ManagedUser{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ManagedUser{}, err
	}
	return s.ManagedUser(ctx, user.ID)
}

func (s *Store) DeleteUser(
	ctx context.Context, id uuid.UUID, actor User, remoteIP string,
) error {
	if id == actor.ID {
		return errors.New("cannot delete the current user")
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var username, role string
	var active bool
	if err := tx.QueryRow(ctx, `SELECT username,role,active FROM users WHERE id=$1 FOR UPDATE`, id).
		Scan(&username, &role, &active); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if role == "admin" && active {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('collector-active-admins'))`); err != nil {
			return err
		}
		var otherAdmins int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM users
			WHERE id<>$1 AND role='admin' AND active`, id).Scan(&otherAdmins); err != nil {
			return err
		}
		if otherAdmins == 0 {
			return errors.New("cannot delete the last active administrator")
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM users WHERE id=$1`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_log
		(actor_id,action,resource_type,resource_id,remote_ip,details)
		VALUES($1,'user_delete','user',$2,$3,$4)`,
		actor.ID, id.String(), nullableIP(remoteIP),
		map[string]string{"username": username, "role": role}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func validRole(role string) bool {
	return role == "admin" || role == "analyst" || role == "viewer"
}

const (
	FirmwareScheme3232 = "3.23.2"
	FirmwareScheme3410 = "3.410"
)

// NormalizeFirmwareScheme maps legacy full builds onto the two supported
// processing schemes. Unknown values fall back to the current 3.23.2 profile.
func NormalizeFirmwareScheme(value string) string {
	value = strings.TrimSpace(value)
	switch value {
	case FirmwareScheme3232, FirmwareScheme3410:
		return value
	}
	if strings.HasPrefix(value, "3.410") {
		return FirmwareScheme3410
	}
	return FirmwareScheme3232
}

// CanonicalFirmware accepts only the UI/API scheme identifiers.
func CanonicalFirmware(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return FirmwareScheme3232, nil
	}
	if value == FirmwareScheme3232 || value == FirmwareScheme3410 {
		return value, nil
	}
	return "", errors.New("firmware must be 3.23.2 or 3.410")
}

func normalizeDeviceFirmware(device *Device) {
	device.Firmware = NormalizeFirmwareScheme(device.Firmware)
}

func (s *Store) ListDevices(ctx context.Context) ([]Device, error) {
	rows, err := s.DB.Query(ctx, `SELECT id,name,model,firmware,timezone,active_timezone,
		timezone_revision,active_timezone_revision,cdr_source_timezone,host(management_ip),
		host(syslog_source_ip),COALESCE(device_sign,''),antifraud_enabled,antifraud_mode,
		ftp_username,ftp_home,cdr_columns,enabled,purge_state,purge_error,created_at
		FROM devices ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Device
	for rows.Next() {
		var device Device
		if err := rows.Scan(&device.ID, &device.Name, &device.Model, &device.Firmware, &device.Timezone,
			&device.ActiveTimezone, &device.TimezoneRevision, &device.ActiveTimezoneRevision,
			&device.CDRSourceTimezone, &device.ManagementIP, &device.SyslogSourceIP, &device.DeviceSign,
			&device.AntifraudEnabled, &device.AntifraudMode, &device.FTPUsername,
			&device.FTPHome, &device.CDRColumns, &device.Enabled, &device.PurgeState,
			&device.PurgeError, &device.CreatedAt); err != nil {
			return nil, err
		}
		normalizeDeviceFirmware(&device)
		result = append(result, device)
	}
	return result, rows.Err()
}

func (s *Store) DeviceBySourceIP(ctx context.Context, sourceIP string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.DB.QueryRow(ctx, `SELECT id FROM devices WHERE syslog_source_ip=$1 AND enabled`, sourceIP).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	return id, err
}

func (s *Store) DeviceIdentityBySourceIP(
	ctx context.Context, sourceIP string,
) (uuid.UUID, string, int64, error) {
	var id uuid.UUID
	var timezone string
	var revision int64
	err := s.DB.QueryRow(ctx,
		`SELECT id,active_timezone,active_timezone_revision
		 FROM devices WHERE syslog_source_ip=$1 AND enabled`, sourceIP).
		Scan(&id, &timezone, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", 0, ErrNotFound
	}
	return id, timezone, revision, err
}

func (s *Store) DeviceCacheRevision() uint64 {
	return s.deviceCacheRevision.Load()
}

func (s *Store) LockDeviceWrites(id uuid.UUID) func() {
	value, _ := s.deviceLocks.LoadOrStore(id, &sync.RWMutex{})
	lock := value.(*sync.RWMutex)
	lock.RLock()
	return lock.RUnlock
}

func (s *Store) LockDevicePurge(id uuid.UUID) func() {
	value, _ := s.deviceLocks.LoadOrStore(id, &sync.RWMutex{})
	lock := value.(*sync.RWMutex)
	lock.Lock()
	return lock.Unlock
}

func (s *Store) Device(ctx context.Context, id uuid.UUID) (Device, error) {
	var device Device
	err := s.DB.QueryRow(ctx, `SELECT id,name,model,firmware,timezone,active_timezone,
		timezone_revision,active_timezone_revision,cdr_source_timezone,host(management_ip),
		host(syslog_source_ip),COALESCE(device_sign,''),antifraud_enabled,antifraud_mode,
		ftp_username,ftp_home,cdr_columns,enabled,purge_state,purge_error,created_at
		FROM devices WHERE id=$1`, id).
		Scan(&device.ID, &device.Name, &device.Model, &device.Firmware, &device.Timezone,
			&device.ActiveTimezone, &device.TimezoneRevision, &device.ActiveTimezoneRevision,
			&device.CDRSourceTimezone, &device.ManagementIP, &device.SyslogSourceIP, &device.DeviceSign,
			&device.AntifraudEnabled, &device.AntifraudMode, &device.FTPUsername,
			&device.FTPHome, &device.CDRColumns, &device.Enabled, &device.PurgeState,
			&device.PurgeError, &device.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	if err != nil {
		return Device{}, err
	}
	normalizeDeviceFirmware(&device)
	return device, nil
}

func (s *Store) DeviceTimezone(ctx context.Context, id uuid.UUID) (string, error) {
	var timezone string
	err := s.DB.QueryRow(ctx, `SELECT timezone FROM devices WHERE id=$1`, id).Scan(&timezone)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return timezone, err
}

func (s *Store) DeviceTimeConfig(ctx context.Context, id uuid.UUID) (DeviceTimeConfig, error) {
	var config DeviceTimeConfig
	var purgeState string
	err := s.DB.QueryRow(ctx, `SELECT active_timezone,active_timezone_revision,
		timezone,timezone_revision,purge_state FROM devices WHERE id=$1`, id).
		Scan(&config.ActiveTimezone, &config.ActiveTimezoneRevision,
			&config.Timezone, &config.TimezoneRevision, &purgeState)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeviceTimeConfig{}, ErrNotFound
	}
	if err == nil && purgeState != "active" {
		return DeviceTimeConfig{}, ErrDeviceDeleting
	}
	return config, err
}

func (s *Store) ActivateDeviceTimezoneRevision(ctx context.Context, id uuid.UUID, revision int64) error {
	commandTag, err := s.DB.Exec(ctx, `UPDATE devices
		SET active_timezone=timezone,active_timezone_revision=timezone_revision
		WHERE id=$1 AND timezone_revision=$2`, id, revision)
	if err != nil {
		return err
	}
	if commandTag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// IngestFileClaim is the durable ledger row for one CDR content hash.
// Retry=false means the file was already ingested successfully and the local
// copy may be deleted. Retry=true means the watcher must (re)process it.
type IngestFileClaim struct {
	ID        uuid.UUID
	ObjectKey string
	Status    string
	RowsValid uint64
	Retry     bool
}

func IngestFileFullyIngested(status string, rowsValid uint64) bool {
	return status == "processed" || (status == "quarantined" && rowsValid > 0)
}

func (s *Store) ClaimIngestFile(
	ctx context.Context, deviceID uuid.UUID, name, objectKey, checksum string, size int64,
) (IngestFileClaim, error) {
	var claim IngestFileClaim
	err := s.DB.QueryRow(ctx, `INSERT INTO ingest_files(device_id,original_name,object_key,sha256,size_bytes,status)
		VALUES($1,$2,$3,$4,$5,'received')
		ON CONFLICT(device_id,sha256) DO NOTHING
		RETURNING id,object_key,status,rows_valid`,
		deviceID, name, objectKey, checksum, size,
	).Scan(&claim.ID, &claim.ObjectKey, &claim.Status, &claim.RowsValid)
	if err == nil {
		claim.Retry = true
		return claim, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return IngestFileClaim{}, err
	}
	err = s.DB.QueryRow(ctx, `SELECT id,object_key,status,rows_valid
		FROM ingest_files WHERE device_id=$1 AND sha256=$2`, deviceID, checksum).
		Scan(&claim.ID, &claim.ObjectKey, &claim.Status, &claim.RowsValid)
	if errors.Is(err, pgx.ErrNoRows) {
		return IngestFileClaim{}, ErrNotFound
	}
	if err != nil {
		return IngestFileClaim{}, err
	}
	if IngestFileFullyIngested(claim.Status, claim.RowsValid) {
		claim.Retry = false
		return claim, nil
	}
	_, err = s.DB.Exec(ctx, `UPDATE ingest_files
		SET original_name=$2,object_key=$3,size_bytes=$4,status='received',
		    error=NULL,processed_at=NULL,rows_total=0,rows_valid=0
		WHERE id=$1`, claim.ID, name, objectKey, size)
	if err != nil {
		return IngestFileClaim{}, err
	}
	claim.ObjectKey = objectKey
	claim.Status = "received"
	claim.RowsValid = 0
	claim.Retry = true
	return claim, nil
}

// RegisterIngestFile keeps the legacy helper for callers that only need a new row id.
func (s *Store) RegisterIngestFile(
	ctx context.Context, deviceID uuid.UUID, name, objectKey, checksum string, size int64,
) (uuid.UUID, error) {
	claim, err := s.ClaimIngestFile(ctx, deviceID, name, objectKey, checksum, size)
	if err != nil {
		return uuid.Nil, err
	}
	if !claim.Retry {
		return uuid.Nil, ErrNotFound
	}
	return claim.ID, nil
}

type IngestFileSummary struct {
	ID           uuid.UUID  `json:"id"`
	OriginalName string     `json:"originalName"`
	Status       string     `json:"status"`
	RowsTotal    uint64     `json:"rowsTotal"`
	RowsValid    uint64     `json:"rowsValid"`
	Error        string     `json:"error,omitempty"`
	ReceivedAt   time.Time  `json:"receivedAt"`
	ProcessedAt  *time.Time `json:"processedAt,omitempty"`
}

func (s *Store) ListRecentIngestFiles(ctx context.Context, deviceID uuid.UUID, limit int) ([]IngestFileSummary, error) {
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	rows, err := s.DB.Query(ctx, `SELECT id,original_name,status,rows_total,rows_valid,
		COALESCE(error,''),received_at,processed_at
		FROM ingest_files WHERE device_id=$1
		ORDER BY received_at DESC LIMIT $2`, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []IngestFileSummary
	for rows.Next() {
		var item IngestFileSummary
		if err := rows.Scan(
			&item.ID, &item.OriginalName, &item.Status, &item.RowsTotal, &item.RowsValid,
			&item.Error, &item.ReceivedAt, &item.ProcessedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) CompleteIngestFile(ctx context.Context, id uuid.UUID, status string, rowsTotal, rowsValid uint64, message string) error {
	_, err := s.DB.Exec(ctx, `UPDATE ingest_files SET status=$2,rows_total=$3,rows_valid=$4,
		error=NULLIF($5,''),processed_at=now() WHERE id=$1`, id, status, rowsTotal, rowsValid, message)
	return err
}

func (s *Store) CreateDevice(ctx context.Context, input NewDevice, actor User, remoteIP string) (Device, error) {
	syslogSourceIP, ok := normalizeHostIP(input.SyslogSourceIP)
	if strings.TrimSpace(input.Name) == "" || !ok {
		return Device{}, errors.New("name and valid syslogSourceIp are required")
	}
	input.SyslogSourceIP = syslogSourceIP
	if input.ManagementIP != "" {
		managementIP, valid := normalizeHostIP(input.ManagementIP)
		if !valid {
			return Device{}, errors.New("managementIp must be empty or a valid IP")
		}
		input.ManagementIP = managementIP
	}
	if input.Model == "" {
		input.Model = "SMG-1016M"
	}
	firmware, err := CanonicalFirmware(input.Firmware)
	if err != nil {
		return Device{}, err
	}
	input.Firmware = firmware
	if input.Timezone == "" {
		input.Timezone = "Asia/Novosibirsk"
	}
	if _, err := time.LoadLocation(input.Timezone); err != nil {
		return Device{}, fmt.Errorf("invalid IANA timezone %q", input.Timezone)
	}
	if input.AntifraudMode == "" {
		input.AntifraudMode = "OFF"
	}
	id := uuid.New()
	ftpUsername := "smg_" + strings.ReplaceAll(id.String()[:13], "-", "")
	ftpPassword, err := randomToken(18)
	if err != nil {
		return Device{}, err
	}
	ftpHome := "/srv/cdr/" + id.String()
	columns, _ := json.Marshal(input.CDRColumns)
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return Device{}, err
	}
	defer tx.Rollback(ctx)
	var device Device
	err = tx.QueryRow(ctx, `INSERT INTO devices
		(id,name,model,firmware,timezone,active_timezone,timezone_revision,
		 active_timezone_revision,cdr_source_timezone,management_ip,syslog_source_ip,device_sign,
		 antifraud_enabled,antifraud_mode,ftp_username,ftp_home,cdr_columns)
		VALUES($1,$2,$3,$4,$5,$5,1,1,$5,NULLIF($6,'')::inet,$7,$8,$9,$10,$11,$12,$13)
		RETURNING id,name,model,firmware,timezone,active_timezone,timezone_revision,
		 active_timezone_revision,cdr_source_timezone,host(management_ip),host(syslog_source_ip),
		 COALESCE(device_sign,''),antifraud_enabled,antifraud_mode,ftp_username,ftp_home,
		 cdr_columns,enabled,purge_state,purge_error,created_at`,
		id, strings.TrimSpace(input.Name), input.Model, input.Firmware, input.Timezone,
		input.ManagementIP, input.SyslogSourceIP, input.DeviceSign, input.AntifraudEnabled,
		input.AntifraudMode, ftpUsername, ftpHome, columns,
	).Scan(&device.ID, &device.Name, &device.Model, &device.Firmware, &device.Timezone,
		&device.ActiveTimezone, &device.TimezoneRevision, &device.ActiveTimezoneRevision,
		&device.CDRSourceTimezone, &device.ManagementIP, &device.SyslogSourceIP, &device.DeviceSign,
		&device.AntifraudEnabled, &device.AntifraudMode, &device.FTPUsername,
		&device.FTPHome, &device.CDRColumns, &device.Enabled, &device.PurgeState,
		&device.PurgeError, &device.CreatedAt)
	if err != nil {
		return Device{}, err
	}
	normalizeDeviceFirmware(&device)
	details, _ := json.Marshal(map[string]any{"name": device.Name, "syslogSourceIp": device.SyslogSourceIP})
	_, err = tx.Exec(ctx, `INSERT INTO audit_log(actor_id,action,resource_type,resource_id,remote_ip,details)
		VALUES($1,'device_create','device',$2,$3,$4)`, actor.ID, id.String(), nullableIP(remoteIP), details)
	if err != nil {
		return Device{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Device{}, err
	}
	s.deviceCacheRevision.Add(1)
	device.GeneratedPassword = ftpPassword
	return device, nil
}

func (s *Store) UpdateDevice(
	ctx context.Context, id uuid.UUID, input DeviceUpdate, actor User, remoteIP string,
) (Device, error) {
	syslogSourceIP, ok := normalizeHostIP(input.SyslogSourceIP)
	if strings.TrimSpace(input.Name) == "" || !ok {
		return Device{}, errors.New("name and valid syslogSourceIp are required")
	}
	input.SyslogSourceIP = syslogSourceIP
	if _, err := time.LoadLocation(input.Timezone); err != nil {
		return Device{}, fmt.Errorf("invalid IANA timezone %q", input.Timezone)
	}
	if input.ManagementIP != "" {
		managementIP, valid := normalizeHostIP(input.ManagementIP)
		if !valid {
			return Device{}, errors.New("managementIp must be empty or a valid IP")
		}
		input.ManagementIP = managementIP
	}
	firmware, err := CanonicalFirmware(input.Firmware)
	if err != nil {
		return Device{}, err
	}
	input.Firmware = firmware
	columns, _ := json.Marshal(input.CDRColumns)
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return Device{}, err
	}
	defer tx.Rollback(ctx)
	var device Device
	err = tx.QueryRow(ctx, `UPDATE devices SET
		name=$2,firmware=$3,
		timezone_revision=CASE WHEN timezone IS DISTINCT FROM $4 THEN timezone_revision+1
			ELSE timezone_revision END,
		timezone=$4,cdr_source_timezone=$4,management_ip=NULLIF($5,'')::inet,
		syslog_source_ip=$6,device_sign=$7,antifraud_enabled=$8,antifraud_mode=$9,
		enabled=$10,cdr_columns=$11
		WHERE id=$1 AND purge_state='active'
		RETURNING id,name,model,firmware,timezone,active_timezone,timezone_revision,
			active_timezone_revision,cdr_source_timezone,host(management_ip),host(syslog_source_ip),
			COALESCE(device_sign,''),antifraud_enabled,antifraud_mode,ftp_username,ftp_home,
			cdr_columns,enabled,purge_state,purge_error,created_at`,
		id, strings.TrimSpace(input.Name), input.Firmware, input.Timezone,
		input.ManagementIP, input.SyslogSourceIP, input.DeviceSign,
		input.AntifraudEnabled, input.AntifraudMode, input.Enabled, columns,
	).Scan(&device.ID, &device.Name, &device.Model, &device.Firmware, &device.Timezone,
		&device.ActiveTimezone, &device.TimezoneRevision, &device.ActiveTimezoneRevision,
		&device.CDRSourceTimezone, &device.ManagementIP, &device.SyslogSourceIP, &device.DeviceSign,
		&device.AntifraudEnabled, &device.AntifraudMode, &device.FTPUsername,
		&device.FTPHome, &device.CDRColumns, &device.Enabled, &device.PurgeState,
		&device.PurgeError, &device.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	if err != nil {
		return Device{}, err
	}
	normalizeDeviceFirmware(&device)
	details, _ := json.Marshal(map[string]any{
		"name": device.Name, "timezone": device.Timezone,
		"syslogSourceIp": device.SyslogSourceIP, "enabled": device.Enabled,
	})
	if _, err := tx.Exec(ctx, `INSERT INTO audit_log
		(actor_id,action,resource_type,resource_id,remote_ip,details)
		VALUES($1,'device_update','device',$2,$3,$4)`,
		actor.ID, id.String(), nullableIP(remoteIP), details); err != nil {
		return Device{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Device{}, err
	}
	s.deviceCacheRevision.Add(1)
	return device, nil
}

func (s *Store) DeleteDevice(ctx context.Context, id uuid.UUID, actor User, remoteIP string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var name string
	if err := tx.QueryRow(ctx, `DELETE FROM devices WHERE id=$1 RETURNING name`, id).Scan(&name); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	details, _ := json.Marshal(map[string]string{"name": name})
	if _, err := tx.Exec(ctx, `INSERT INTO audit_log(actor_id,action,resource_type,resource_id,remote_ip,details)
		VALUES($1,'device_delete','device',$2,$3,$4)`, actor.ID, id.String(), nullableIP(remoteIP), details); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.deviceCacheRevision.Add(1)
	return nil
}

func (s *Store) BeginDevicePurge(ctx context.Context, id uuid.UUID) (Device, error) {
	tag, err := s.DB.Exec(ctx, `UPDATE devices
		SET enabled=false,purge_state='deleting',purge_error='',purge_updated_at=now()
		WHERE id=$1`, id)
	if err != nil {
		return Device{}, err
	}
	if tag.RowsAffected() == 0 {
		return Device{}, ErrNotFound
	}
	s.deviceCacheRevision.Add(1)
	return s.Device(ctx, id)
}

func (s *Store) FailDevicePurge(ctx context.Context, id uuid.UUID, phase string, purgeErr error) error {
	message := "unknown purge error"
	if purgeErr != nil {
		message = purgeErr.Error()
	}
	if phase != "" {
		message = phase + ": " + message
	}
	_, err := s.DB.Exec(ctx, `UPDATE devices
		SET purge_state='purge_failed',purge_error=$2,purge_updated_at=now()
		WHERE id=$1`, id, message)
	return err
}

func (s *Store) FinalizeDevicePurge(ctx context.Context, id uuid.UUID) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM ingest_files WHERE device_id=$1`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM export_jobs WHERE device_id=$1`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM audit_log
		WHERE resource_type='device' AND resource_id=$1`, id.String()); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM devices WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.deviceCacheRevision.Add(1)
	s.deviceLocks.Delete(id)
	return nil
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=2$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return false
	}
	var memory uint32
	var iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expected)))
	return equalBytes(actual, expected)
}

func randomToken(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func nullableIP(value string) any {
	host, _, err := net.SplitHostPort(value)
	if err == nil {
		value = host
	}
	value = strings.Trim(value, "[]")
	if net.ParseIP(value) == nil {
		return nil
	}
	return value
}

func normalizeHostIP(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), true
	}
	ip, network, err := net.ParseCIDR(value)
	if err != nil {
		return "", false
	}
	ones, bits := network.Mask.Size()
	if ones != bits {
		return "", false
	}
	return ip.String(), true
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var value byte
	for index := range left {
		value |= left[index] ^ right[index]
	}
	return value == 0
}
