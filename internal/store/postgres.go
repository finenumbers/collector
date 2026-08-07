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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"collector/internal/equipment"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/argon2"
)

var (
	ErrNotFound       = errors.New("not found")
	ErrDeviceDeleting = errors.New("device is being deleted")
)

const clickHouseHeavyLaneLockKey int64 = 0x43484c414e453031

type Store struct {
	DB                  *pgxpool.Pool
	deviceCacheRevision atomic.Uint64
	deviceLocks         sync.Map
	ingestSummaryMu     sync.Mutex
	ingestSummaryAt     time.Time
	ingestSummaryCache  map[uuid.UUID]DeviceIngestSummary
}

// AcquireClickHouseHeavyLane is a deployment-wide export/custom-replay lane.
// It uses a dedicated PostgreSQL session so split roles cannot overlap heavy
// warehouse work. Callers acquire it before workload admission and device locks.
func (s *Store) AcquireClickHouseHeavyLane(ctx context.Context) (func(), error) {
	conn, err := s.DB.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		var acquired bool
		if err = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`,
			clickHouseHeavyLaneLockKey).Scan(&acquired); err != nil {
			conn.Release()
			return nil, err
		}
		if acquired {
			var once sync.Once
			return func() {
				once.Do(func() {
					unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					var unlocked bool
					unlockErr := conn.QueryRow(unlockCtx, `SELECT pg_advisory_unlock($1)`,
						clickHouseHeavyLaneLockKey).Scan(&unlocked)
					if unlockErr != nil || !unlocked {
						_ = conn.Conn().Close(context.Background())
					}
					conn.Release()
				})
			}, nil
		}
		select {
		case <-ctx.Done():
			conn.Release()
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
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
	ID                     uuid.UUID              `json:"id"`
	Name                   string                 `json:"name"`
	SourceCategory         string                 `json:"sourceCategory"`
	TemplateKey            string                 `json:"templateKey"`
	Capabilities           equipment.Capabilities `json:"capabilities"`
	Model                  string                 `json:"model"`
	Firmware               string                 `json:"firmware"`
	Timezone               string                 `json:"timezone"`
	ActiveTimezone         string                 `json:"activeTimezone"`
	TimezoneRevision       int64                  `json:"timezoneRevision"`
	ActiveTimezoneRevision int64                  `json:"activeTimezoneRevision"`
	CDRSourceTimezone      string                 `json:"cdrSourceTimezone"`
	ManagementIP           *string                `json:"managementIp,omitempty"`
	SyslogSourceIP         string                 `json:"syslogSourceIp"`
	DeviceSign             string                 `json:"deviceSign"`
	AntifraudEnabled       bool                   `json:"antifraudEnabled"`
	VoipmonitorEnabled     bool                   `json:"voipmonitorEnabled"`
	FTPUsername            string                 `json:"ftpUsername"`
	FTPHome                string                 `json:"ftpHome"`
	Enabled                bool                   `json:"enabled"`
	SyslogArchiveEnabled   bool                   `json:"syslogArchiveEnabled"`
	SyslogArchiveRemoteDir string                 `json:"syslogArchiveRemoteDir"`
	PurgeState             string                 `json:"purgeState"`
	PurgeError             string                 `json:"purgeError,omitempty"`
	DetectionStatus        string                 `json:"detectionStatus"`
	DetectionTemplate      string                 `json:"detectionTemplate,omitempty"`
	DetectionFingerprint   string                 `json:"detectionFingerprint,omitempty"`
	DetectionError         string                 `json:"detectionError,omitempty"`
	DetectionCheckedAt     *time.Time             `json:"detectionCheckedAt,omitempty"`
	DetectionLastFileAt    *time.Time             `json:"detectionLastFileAt,omitempty"`
	CreatedAt              time.Time              `json:"createdAt"`
	GeneratedPassword      string                 `json:"generatedPassword,omitempty"`
}

type DeviceTimeConfig struct {
	ActiveTimezone         string `json:"activeTimezone"`
	ActiveTimezoneRevision int64  `json:"activeTimezoneRevision"`
	Timezone               string `json:"timezone"`
	TimezoneRevision       int64  `json:"timezoneRevision"`
	TemplateKey            string `json:"templateKey"`
	Firmware               string `json:"firmware"`
}

type NewDevice struct {
	Name             string `json:"name"`
	SourceCategory   string `json:"sourceCategory"`
	TemplateKey      string `json:"templateKey"`
	Model            string `json:"model"`
	Firmware         string `json:"firmware"`
	Timezone         string `json:"timezone"`
	ManagementIP     string `json:"managementIp"`
	SyslogSourceIP     string `json:"syslogSourceIp"`
	DeviceSign         string `json:"deviceSign"`
	AntifraudEnabled   bool   `json:"antifraudEnabled"`
	VoipmonitorEnabled bool   `json:"voipmonitorEnabled"`
}

type DeviceUpdate struct {
	Name                   string  `json:"name"`
	SourceCategory         string  `json:"sourceCategory"`
	TemplateKey            string  `json:"templateKey"`
	Firmware               string  `json:"firmware"`
	Timezone               string  `json:"timezone"`
	ManagementIP           string  `json:"managementIp"`
	SyslogSourceIP         string  `json:"syslogSourceIp"`
	DeviceSign             string  `json:"deviceSign"`
	AntifraudEnabled       bool    `json:"antifraudEnabled"`
	VoipmonitorEnabled     bool    `json:"voipmonitorEnabled"`
	Enabled                bool    `json:"enabled"`
	SyslogArchiveEnabled   *bool   `json:"syslogArchiveEnabled,omitempty"`
	SyslogArchiveRemoteDir *string `json:"syslogArchiveRemoteDir,omitempty"`
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
		session.CSRF = csrf
	} else if csrf != "" {
		provided := sha256.Sum256([]byte(csrf))
		if equalBytes(provided[:], csrfHash) {
			session.CSRF = csrf
		}
	}
	if _, err := s.DB.Exec(ctx, `UPDATE sessions SET last_seen_at=now() WHERE id_hash=$1`, tokenHash[:]); err != nil {
		return Session{}, err
	}
	return session, nil
}

// RotateSessionCSRF issues a fresh CSRF secret for an existing browser session.
// Needed after page reload: the session cookie survives, but the SPA loses the
// in-memory CSRF token and only the hash is stored server-side.
func (s *Store) RotateSessionCSRF(ctx context.Context, token string) (string, error) {
	csrf, err := randomToken(24)
	if err != nil {
		return "", err
	}
	tokenHash := sha256.Sum256([]byte(token))
	csrfHash := sha256.Sum256([]byte(csrf))
	tag, err := s.DB.Exec(ctx, `UPDATE sessions SET csrf_hash=$2, last_seen_at=now()
		WHERE id_hash=$1 AND expires_at>now()`, tokenHash[:], csrfHash[:])
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() == 0 {
		return "", ErrNotFound
	}
	return csrf, nil
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

func normalizeDeviceFirmware(device *Device) {
	if device.SourceCategory == equipment.CategoryEquipment {
		device.Firmware = NormalizeFirmwareScheme(device.Firmware)
	}
	if template, err := equipment.Resolve(device.TemplateKey); err == nil {
		device.Capabilities = template.Capabilities
	}
}

func (s *Store) ListDevices(ctx context.Context) ([]Device, error) {
	return s.ListDevicesByCategory(ctx, "")
}

const deviceSelectColumns = `id,name,source_category,template_key,model,firmware,timezone,active_timezone,
		timezone_revision,active_timezone_revision,cdr_source_timezone,host(management_ip),
		COALESCE(host(syslog_source_ip),''),COALESCE(device_sign,''),antifraud_enabled,
		COALESCE(voipmonitor_enabled,false),ftp_username,ftp_home,enabled,purge_state,purge_error,
		detection_status,detection_template,detection_fingerprint,detection_error,detection_checked_at,
		detection_last_file_at,created_at,
		COALESCE(syslog_archive_enabled,false),COALESCE(syslog_archive_remote_dir,'')`

func scanDeviceRow(row interface {
	Scan(dest ...any) error
}, device *Device) error {
	return row.Scan(&device.ID, &device.Name, &device.SourceCategory, &device.TemplateKey,
		&device.Model, &device.Firmware, &device.Timezone,
		&device.ActiveTimezone, &device.TimezoneRevision, &device.ActiveTimezoneRevision,
		&device.CDRSourceTimezone, &device.ManagementIP, &device.SyslogSourceIP, &device.DeviceSign,
		&device.AntifraudEnabled, &device.VoipmonitorEnabled, &device.FTPUsername,
		&device.FTPHome, &device.Enabled, &device.PurgeState,
		&device.PurgeError, &device.DetectionStatus, &device.DetectionTemplate,
		&device.DetectionFingerprint, &device.DetectionError, &device.DetectionCheckedAt,
		&device.DetectionLastFileAt, &device.CreatedAt,
		&device.SyslogArchiveEnabled, &device.SyslogArchiveRemoteDir)
}

func (s *Store) ListDevicesByCategory(ctx context.Context, category string) ([]Device, error) {
	if category != "" && category != equipment.CategoryEquipment && category != equipment.CategorySoftswitch {
		return nil, errors.New("category must be equipment or softswitch")
	}
	rows, err := s.DB.Query(ctx, `SELECT `+deviceSelectColumns+`
		FROM devices WHERE ($1='' OR source_category=$1) ORDER BY name`, category)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Device
	for rows.Next() {
		var device Device
		if err := scanDeviceRow(rows, &device); err != nil {
			return nil, err
		}
		normalizeDeviceFirmware(&device)
		result = append(result, device)
	}
	return result, rows.Err()
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
	lock.Lock()
	return lock.Unlock
}

func (s *Store) LockDevicePurge(id uuid.UUID) func() {
	value, _ := s.deviceLocks.LoadOrStore(id, &sync.RWMutex{})
	lock := value.(*sync.RWMutex)
	lock.Lock()
	return lock.Unlock
}

func (s *Store) Device(ctx context.Context, id uuid.UUID) (Device, error) {
	var device Device
	err := scanDeviceRow(s.DB.QueryRow(ctx, `SELECT `+deviceSelectColumns+` FROM devices WHERE id=$1`, id), &device)
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	if err != nil {
		return Device{}, err
	}
	normalizeDeviceFirmware(&device)
	return device, nil
}

func (s *Store) DeviceTimeConfig(ctx context.Context, id uuid.UUID) (DeviceTimeConfig, error) {
	var config DeviceTimeConfig
	var purgeState string
	err := s.DB.QueryRow(ctx, `SELECT active_timezone,active_timezone_revision,
		timezone,timezone_revision,template_key,firmware,purge_state FROM devices WHERE id=$1`, id).
		Scan(&config.ActiveTimezone, &config.ActiveTimezoneRevision,
			&config.Timezone, &config.TimezoneRevision, &config.TemplateKey,
			&config.Firmware, &purgeState)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeviceTimeConfig{}, ErrNotFound
	}
	if err == nil && purgeState != "active" {
		return DeviceTimeConfig{}, ErrDeviceDeleting
	}
	return config, err
}

// IngestFileClaim is the durable ledger row for one CDR content hash.
// Retry=false means the file was already ingested successfully and the local
// copy may be deleted. Retry=true means the watcher must (re)process it.
type IngestFileClaim struct {
	ID          uuid.UUID
	ObjectKey   string
	Status      string
	RowsValid   uint64
	Retry       bool
	RemoveLocal bool
}

type IngestFileSummary struct {
	ID              uuid.UUID  `json:"id"`
	OriginalName    string     `json:"originalName"`
	SHA256          string     `json:"sha256"`
	SizeBytes       int64      `json:"sizeBytes"`
	Status          string     `json:"status"`
	RowsTotal       uint64     `json:"rowsTotal"`
	RowsValid       uint64     `json:"rowsValid"`
	Error           string     `json:"error,omitempty"`
	ParserTemplate  string     `json:"parserTemplate"`
	ParserVersion   string     `json:"parserVersion"`
	ReplayState     string     `json:"replayState"`
	ReplayTemplate  string     `json:"replayTemplate,omitempty"`
	ReplayVersion   string     `json:"replayVersion,omitempty"`
	ReplayAttempts  uint32     `json:"replayAttempts"`
	ReplayError     string     `json:"replayError,omitempty"`
	ReceivedAt      time.Time  `json:"receivedAt"`
	ProcessedAt     *time.Time `json:"processedAt,omitempty"`
	ReplayRequested *time.Time `json:"replayRequestedAt,omitempty"`
	ReplayCompleted *time.Time `json:"replayCompletedAt,omitempty"`
}

func (s *Store) ListRecentIngestFiles(ctx context.Context, deviceID uuid.UUID, limit int) ([]IngestFileSummary, error) {
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	rows, err := s.DB.Query(ctx, `SELECT id,original_name,sha256,size_bytes,status,rows_total,rows_valid,
		COALESCE(error,''),parser_template,parser_version,replay_state,
		COALESCE(replay_template,''),COALESCE(replay_version,''),replay_attempts,
		COALESCE(replay_error,''),received_at,processed_at,replay_requested_at,replay_completed_at
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
			&item.ID, &item.OriginalName, &item.SHA256, &item.SizeBytes,
			&item.Status, &item.RowsTotal, &item.RowsValid,
			&item.Error, &item.ParserTemplate, &item.ParserVersion, &item.ReplayState,
			&item.ReplayTemplate, &item.ReplayVersion, &item.ReplayAttempts,
			&item.ReplayError, &item.ReceivedAt, &item.ProcessedAt,
			&item.ReplayRequested, &item.ReplayCompleted,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

type IngestFileObject struct {
	IngestFileSummary
	ObjectKey string
}

func (s *Store) IngestFile(ctx context.Context, deviceID, fileID uuid.UUID) (IngestFileObject, error) {
	var item IngestFileObject
	err := s.DB.QueryRow(ctx, `SELECT id,original_name,sha256,size_bytes,status,
		rows_total,rows_valid,COALESCE(error,''),parser_template,parser_version,replay_state,
		COALESCE(replay_template,''),COALESCE(replay_version,''),replay_attempts,
		COALESCE(replay_error,''),received_at,processed_at,replay_requested_at,replay_completed_at,
		object_key
		FROM ingest_files WHERE device_id=$1 AND id=$2`, deviceID, fileID).Scan(
		&item.ID, &item.OriginalName, &item.SHA256, &item.SizeBytes, &item.Status,
		&item.RowsTotal, &item.RowsValid, &item.Error, &item.ParserTemplate,
		&item.ParserVersion, &item.ReplayState, &item.ReplayTemplate,
		&item.ReplayVersion, &item.ReplayAttempts, &item.ReplayError, &item.ReceivedAt,
		&item.ProcessedAt, &item.ReplayRequested, &item.ReplayCompleted, &item.ObjectKey,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return IngestFileObject{}, ErrNotFound
	}
	return item, err
}

type IngestFileMetrics struct {
	Files    uint64     `json:"files"`
	Bytes    uint64     `json:"bytes"`
	LatestAt *time.Time `json:"latestAt,omitempty"`
}

type IngestReplayProgress struct {
	Pending     uint64 `json:"pending"`
	Processing  uint64 `json:"processing"`
	Complete    uint64 `json:"complete"`
	Quarantined uint64 `json:"quarantined"`
}

type DeviceIngestSummary struct {
	Replay  IngestReplayProgress
	Metrics IngestFileMetrics
}

func (s *Store) DeviceIngestSummaries(
	ctx context.Context,
) (map[uuid.UUID]DeviceIngestSummary, error) {
	const ttl = 2 * time.Second
	s.ingestSummaryMu.Lock()
	if s.ingestSummaryCache != nil && time.Since(s.ingestSummaryAt) < ttl {
		cached := cloneDeviceIngestSummaries(s.ingestSummaryCache)
		s.ingestSummaryMu.Unlock()
		return cached, nil
	}
	s.ingestSummaryMu.Unlock()

	rows, err := s.DB.Query(ctx, `SELECT device_id,
		count(*) FILTER (WHERE replay_state='pending'),
		count(*) FILTER (WHERE replay_state='processing'),
		count(*) FILTER (WHERE replay_state='complete'),
		count(*) FILTER (WHERE replay_state='complete' AND status='quarantined'),
		count(*) FILTER (WHERE status IN ('archived','processed','quarantined')),
		COALESCE(sum(size_bytes) FILTER
			(WHERE status IN ('archived','processed','quarantined')),0),
		max(received_at) FILTER (WHERE status IN ('archived','processed','quarantined'))
		FROM ingest_files GROUP BY device_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[uuid.UUID]DeviceIngestSummary)
	for rows.Next() {
		var id uuid.UUID
		var summary DeviceIngestSummary
		if err = rows.Scan(
			&id, &summary.Replay.Pending, &summary.Replay.Processing,
			&summary.Replay.Complete, &summary.Replay.Quarantined,
			&summary.Metrics.Files, &summary.Metrics.Bytes, &summary.Metrics.LatestAt,
		); err != nil {
			return nil, err
		}
		result[id] = summary
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	s.ingestSummaryMu.Lock()
	s.ingestSummaryCache = cloneDeviceIngestSummaries(result)
	s.ingestSummaryAt = time.Now()
	s.ingestSummaryMu.Unlock()
	return result, nil
}

func cloneDeviceIngestSummaries(
	source map[uuid.UUID]DeviceIngestSummary,
) map[uuid.UUID]DeviceIngestSummary {
	cloned := make(map[uuid.UUID]DeviceIngestSummary, len(source))
	for id, summary := range source {
		cloned[id] = summary
	}
	return cloned
}

func (s *Store) DeviceIngestReplayProgress(
	ctx context.Context, deviceID uuid.UUID,
) (IngestReplayProgress, error) {
	var progress IngestReplayProgress
	err := s.DB.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE replay_state='pending'),
		count(*) FILTER (WHERE replay_state='processing'),
		count(*) FILTER (WHERE replay_state='complete'),
		count(*) FILTER (WHERE replay_state='complete' AND status='quarantined')
		FROM ingest_files WHERE device_id=$1`, deviceID).Scan(
		&progress.Pending, &progress.Processing, &progress.Complete, &progress.Quarantined,
	)
	return progress, err
}

func (s *Store) AuditIngestFileDownload(
	ctx context.Context, fileID uuid.UUID, actor User, remoteIP string,
) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO audit_log
		(actor_id,action,resource_type,resource_id,remote_ip)
		VALUES($1,'ingest_file_download','ingest_file',$2,$3)`,
		actor.ID, fileID.String(), nullableIP(remoteIP))
	return err
}

func (s *Store) CompleteIngestFile(ctx context.Context, id uuid.UUID, status string, rowsTotal, rowsValid uint64, message string) error {
	_, err := s.DB.Exec(ctx, `UPDATE ingest_files SET status=$2,rows_total=$3,rows_valid=$4,
		error=NULLIF($5,''),processed_at=now() WHERE id=$1`, id, status, rowsTotal, rowsValid, message)
	return err
}

func (s *Store) CompleteIngestFileWithParser(
	ctx context.Context,
	id uuid.UUID,
	status string,
	rowsTotal, rowsValid uint64,
	message, parserTemplate, parserVersion string,
) error {
	_, err := s.DB.Exec(ctx, `UPDATE ingest_files
		SET status=$2,rows_total=$3,rows_valid=$4,error=NULLIF($5,''),processed_at=now(),
			parser_template=$6,parser_version=$7
		WHERE id=$1`,
		id, status, rowsTotal, rowsValid, message, parserTemplate, parserVersion)
	return err
}

type IngestReplayClaim struct {
	ID             uuid.UUID
	DeviceID       uuid.UUID
	ObjectKey      string
	OriginalName   string
	ReplayTemplate string
	ReplayVersion  string
	Attempts       uint32
}

func (s *Store) ClaimNextIngestReplay(ctx context.Context) (IngestReplayClaim, error) {
	var claim IngestReplayClaim
	err := s.DB.QueryRow(ctx, `WITH candidate AS
		(
			SELECT f.id FROM ingest_files f JOIN devices d ON d.id=f.device_id
			WHERE d.enabled AND d.purge_state='active' AND
			  (f.replay_state='pending'
			   OR (f.replay_state='processing'
			       AND f.replay_started_at < now()-interval '5 minutes'))
			ORDER BY f.replay_requested_at,f.id
			FOR UPDATE OF f SKIP LOCKED
			LIMIT 1
		)
		UPDATE ingest_files AS f
		SET replay_state='processing',replay_started_at=now(),
			replay_attempts=f.replay_attempts+1,replay_error=NULL
		FROM candidate
		WHERE f.id=candidate.id
		RETURNING f.id,f.device_id,f.object_key,f.original_name,
			f.replay_template,f.replay_version,f.replay_attempts`).
		Scan(
			&claim.ID, &claim.DeviceID, &claim.ObjectKey, &claim.OriginalName,
			&claim.ReplayTemplate, &claim.ReplayVersion, &claim.Attempts,
		)
	if errors.Is(err, pgx.ErrNoRows) {
		return IngestReplayClaim{}, ErrNotFound
	}
	return claim, err
}

func (s *Store) RetryIngestReplay(
	ctx context.Context, id uuid.UUID, replayErr error,
) error {
	message := "unknown replay error"
	if replayErr != nil {
		message = replayErr.Error()
	}
	_, err := s.DB.Exec(ctx, `UPDATE ingest_files
		SET replay_state='pending',replay_started_at=NULL,replay_error=$2
		WHERE id=$1 AND replay_state='processing'`, id, message)
	return err
}

func (s *Store) CompleteIngestReplay(
	ctx context.Context,
	id uuid.UUID,
	status string,
	rowsTotal, rowsValid uint64,
	message, parserTemplate, parserVersion string,
) error {
	_, err := s.DB.Exec(ctx, `UPDATE ingest_files
		SET status=$2,rows_total=$3,rows_valid=$4,error=NULLIF($5,''),
			processed_at=now(),parser_template=$6,parser_version=$7,
			replay_state='complete',replay_completed_at=now(),replay_error=NULL
		WHERE id=$1 AND replay_state='processing'`,
		id, status, rowsTotal, rowsValid, message, parserTemplate, parserVersion)
	return err
}

func (s *Store) CreateDevice(ctx context.Context, input NewDevice, actor User, remoteIP string) (Device, error) {
	if strings.TrimSpace(input.Name) == "" {
		return Device{}, errors.New("name is required")
	}
	if input.TemplateKey == "" {
		input.TemplateKey = equipment.EltexTemplateForFirmware(NormalizeFirmwareScheme(input.Firmware))
	}
	template, err := equipment.Resolve(input.TemplateKey)
	if err != nil {
		return Device{}, err
	}
	if input.SourceCategory == "" {
		input.SourceCategory = template.Category
	}
	if input.SourceCategory != template.Category {
		return Device{}, errors.New("sourceCategory does not match templateKey")
	}
	if template.Capabilities.Syslog {
		syslogSourceIP, ok := normalizeHostIP(input.SyslogSourceIP)
		if !ok {
			return Device{}, errors.New("valid syslogSourceIp is required")
		}
		input.SyslogSourceIP = syslogSourceIP
	} else if input.SyslogSourceIP != "" || input.AntifraudEnabled {
		return Device{}, errors.New("softswitch template does not support syslog or AntiFraud/RADIUS")
	}
	if input.ManagementIP != "" {
		managementIP, valid := normalizeHostIP(input.ManagementIP)
		if !valid {
			return Device{}, errors.New("managementIp must be empty or a valid IP")
		}
		input.ManagementIP = managementIP
	}
	if template.Category == equipment.CategorySoftswitch {
		input.Model = "Softswitch"
		input.Firmware = template.Key
		input.ManagementIP = ""
		input.DeviceSign = ""
	} else if input.Model == "" {
		input.Model = "SMG-1016M"
	}
	if template.Category == equipment.CategoryEquipment {
		switch template.Key {
		case equipment.TemplateEltex3410:
			input.Firmware = FirmwareScheme3410
		case equipment.TemplateEltex3232:
			input.Firmware = FirmwareScheme3232
		}
	}
	if input.Timezone == "" && template.Category == equipment.CategorySoftswitch {
		return Device{}, errors.New("timezone is required")
	} else if input.Timezone == "" {
		input.Timezone = "Asia/Novosibirsk"
	}
	if _, err := time.LoadLocation(input.Timezone); err != nil {
		return Device{}, fmt.Errorf("invalid IANA timezone %q", input.Timezone)
	}
	id := uuid.New()
	ftpPrefix := "smg_"
	if template.Category == equipment.CategorySoftswitch {
		ftpPrefix = "ssw_"
	}
	ftpUsername := ftpPrefix + strings.ReplaceAll(id.String()[:13], "-", "")
	ftpPassword, err := randomToken(18)
	if err != nil {
		return Device{}, err
	}
	ftpHome := "/srv/cdr/" + id.String()
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return Device{}, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1::text,$2))`,
		id.String(), customProjectionAdvisorySeed,
	); err != nil {
		return Device{}, err
	}
	var device Device
	err = scanDeviceRow(tx.QueryRow(ctx, `INSERT INTO devices
		(id,name,source_category,template_key,model,firmware,timezone,active_timezone,timezone_revision,
		 active_timezone_revision,cdr_source_timezone,management_ip,syslog_source_ip,device_sign,
		 antifraud_enabled,voipmonitor_enabled,ftp_username,ftp_home)
		VALUES($1,$2,$3,$4,$5,$6,$7,$7,1,1,$7,NULLIF($8,'')::inet,NULLIF($9,'')::inet,$10,$11,$12,$13,$14)
		RETURNING `+deviceSelectColumns,
		id, strings.TrimSpace(input.Name), input.SourceCategory, input.TemplateKey,
		input.Model, input.Firmware, input.Timezone,
		input.ManagementIP, input.SyslogSourceIP, input.DeviceSign, input.AntifraudEnabled,
		input.VoipmonitorEnabled, ftpUsername, ftpHome,
	), &device)
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
	projectionState := "disabled"
	if device.AntifraudEnabled {
		projectionState = "backfilling"
	}
	if _, err := tx.Exec(ctx, `INSERT INTO custom_projection_watermarks
		(device_id,policy_revision,state) VALUES($1,1,$2)`, id, projectionState); err != nil {
		return Device{}, err
	}
	if device.AntifraudEnabled {
		if _, err := tx.Exec(ctx, `INSERT INTO custom_projection_jobs
			(device_id,policy_revision,kind) VALUES($1,1,'discover')`, id); err != nil {
			return Device{}, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO custom_reconciliation_jobs
			(device_id,policy_revision,kind) VALUES($1,1,'discover')`, id); err != nil {
			return Device{}, err
		}
	}
	if device.VoipmonitorEnabled {
		if _, err := tx.Exec(ctx, `INSERT INTO voipmonitor_match_jobs
			(device_id,policy_revision,kind,generation) VALUES($1,1,'discover',1)`, id); err != nil {
			return Device{}, err
		}
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
	release := s.LockDevicePurge(id)
	defer release()
	current, err := s.Device(ctx, id)
	if err != nil {
		return Device{}, err
	}
	if strings.TrimSpace(input.Name) == "" {
		return Device{}, errors.New("name is required")
	}
	if input.TemplateKey == "" {
		if current.SourceCategory == equipment.CategoryEquipment {
			input.TemplateKey = equipment.EltexTemplateForFirmware(
				NormalizeFirmwareScheme(input.Firmware),
			)
		} else {
			input.TemplateKey = current.TemplateKey
		}
	}
	template, err := equipment.Resolve(input.TemplateKey)
	if err != nil {
		return Device{}, err
	}
	if input.SourceCategory == "" {
		input.SourceCategory = template.Category
	}
	if input.SourceCategory != template.Category {
		return Device{}, errors.New("sourceCategory does not match templateKey")
	}
	if current.SourceCategory != template.Category {
		return Device{}, errors.New("sourceCategory cannot be changed")
	}
	if template.Capabilities.Syslog {
		syslogSourceIP, ok := normalizeHostIP(input.SyslogSourceIP)
		if !ok {
			return Device{}, errors.New("valid syslogSourceIp is required")
		}
		input.SyslogSourceIP = syslogSourceIP
	} else if input.SyslogSourceIP != "" || input.AntifraudEnabled {
		return Device{}, errors.New("softswitch template does not support syslog or AntiFraud/RADIUS")
	}
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
	if template.Category == equipment.CategorySoftswitch {
		input.Firmware = template.Key
		input.ManagementIP = ""
		input.DeviceSign = ""
		input.AntifraudEnabled = false
	} else {
		switch template.Key {
		case equipment.TemplateEltex3410:
			input.Firmware = FirmwareScheme3410
		case equipment.TemplateEltex3232:
			input.Firmware = FirmwareScheme3232
		}
	}
	if input.SyslogArchiveRemoteDir != nil {
		dir := strings.TrimSpace(*input.SyslogArchiveRemoteDir)
		if dir != "" && (strings.Contains(dir, "..") || strings.ContainsRune(dir, 0)) {
			return Device{}, errors.New("syslogArchiveRemoteDir contains invalid characters")
		}
		*input.SyslogArchiveRemoteDir = dir
	}
	// Raw Syslog has no timezone-derived projection. CDR reinterpretation is
	// independent, so the control-plane timezone can become active immediately.
	activateTimezoneImmediately := true
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return Device{}, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1::text,$2))`,
		id.String(), customProjectionAdvisorySeed,
	); err != nil {
		return Device{}, err
	}
	var persistedAntifraudEnabled bool
	var persistedVoipmonitorEnabled bool
	if err := tx.QueryRow(ctx, `SELECT antifraud_enabled,COALESCE(voipmonitor_enabled,false)
		FROM devices WHERE id=$1 FOR UPDATE`, id).
		Scan(&persistedAntifraudEnabled, &persistedVoipmonitorEnabled); err != nil {
		return Device{}, err
	}
	var device Device
	err = scanDeviceRow(tx.QueryRow(ctx, `UPDATE devices SET
		name=$2,source_category=$3,template_key=$4,firmware=$5,
		timezone_revision=CASE WHEN timezone IS DISTINCT FROM $6 THEN timezone_revision+1
			ELSE timezone_revision END,
		active_timezone=CASE WHEN $13 THEN $6 ELSE active_timezone END,
		active_timezone_revision=CASE WHEN $13 AND timezone IS DISTINCT FROM $6
			THEN timezone_revision+1
			WHEN $13 THEN timezone_revision
			ELSE active_timezone_revision END,
		timezone=$6,cdr_source_timezone=$6,management_ip=NULLIF($7,'')::inet,
		syslog_source_ip=NULLIF($8,'')::inet,device_sign=$9,
		antifraud_policy_revision=CASE WHEN antifraud_enabled IS DISTINCT FROM $10
			THEN antifraud_policy_revision+1 ELSE antifraud_policy_revision END,
		antifraud_enabled=$10,
		voipmonitor_policy_revision=CASE WHEN voipmonitor_enabled IS DISTINCT FROM $11
			THEN voipmonitor_policy_revision+1 ELSE voipmonitor_policy_revision END,
		voipmonitor_enabled=$11,
		enabled=$12,
		syslog_archive_enabled=COALESCE($14, syslog_archive_enabled),
		syslog_archive_remote_dir=COALESCE($15, syslog_archive_remote_dir)
		WHERE id=$1 AND purge_state='active'
		RETURNING `+deviceSelectColumns,
		id, strings.TrimSpace(input.Name), input.SourceCategory, input.TemplateKey,
		input.Firmware, input.Timezone,
		input.ManagementIP, input.SyslogSourceIP, input.DeviceSign,
		input.AntifraudEnabled, input.VoipmonitorEnabled, input.Enabled, activateTimezoneImmediately,
		input.SyslogArchiveEnabled, input.SyslogArchiveRemoteDir,
	), &device)
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
	if persistedAntifraudEnabled != device.AntifraudEnabled {
		var revision uint64
		if err := tx.QueryRow(ctx,
			`SELECT antifraud_policy_revision FROM devices WHERE id=$1`, id,
		).Scan(&revision); err != nil {
			return Device{}, err
		}
		if _, err := tx.Exec(ctx, `UPDATE custom_projection_jobs
			SET status='cancelled',completed_at=now(),lease_expires_at=NULL,
				worker_id=NULL,updated_at=now()
			WHERE device_id=$1 AND status IN ('pending','running')`, id); err != nil {
			return Device{}, err
		}
		if _, err := tx.Exec(ctx, `UPDATE custom_reconciliation_jobs
			SET status='cancelled',completed_at=now(),lease_expires_at=NULL,
				worker_id=NULL,updated_at=now()
			WHERE device_id=$1 AND status IN ('pending','running')`, id); err != nil {
			return Device{}, err
		}
		kind, state := "disable", "disabled"
		if device.AntifraudEnabled {
			kind, state = "discover", "backfilling"
		}
		if _, err := tx.Exec(ctx, `INSERT INTO custom_projection_watermarks
			(device_id,policy_revision,state) VALUES($1,$2,$3)
			ON CONFLICT (device_id) DO UPDATE SET
				policy_revision=EXCLUDED.policy_revision,state=EXCLUDED.state,
				previous_snapshot_id=custom_projection_watermarks.active_snapshot_id,
				active_snapshot_id=CASE WHEN EXCLUDED.state='disabled' THEN NULL
					ELSE custom_projection_watermarks.active_snapshot_id END,
				updated_at=now()`, id, revision, state); err != nil {
			return Device{}, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO custom_projection_jobs
			(device_id,policy_revision,kind) VALUES($1,$2,$3)`,
			id, revision, kind); err != nil {
			return Device{}, err
		}
		if device.AntifraudEnabled {
			if _, err := tx.Exec(ctx, `INSERT INTO custom_reconciliation_jobs
				(device_id,policy_revision,kind) VALUES($1,$2,'discover')`,
				id, revision); err != nil {
				return Device{}, err
			}
		}
	}
	if persistedVoipmonitorEnabled != device.VoipmonitorEnabled {
		var revision uint64
		if err := tx.QueryRow(ctx,
			`SELECT voipmonitor_policy_revision FROM devices WHERE id=$1`, id,
		).Scan(&revision); err != nil {
			return Device{}, err
		}
		if _, err := tx.Exec(ctx, `UPDATE voipmonitor_match_jobs
			SET status='cancelled',completed_at=now(),lease_expires_at=NULL,
				worker_id=NULL,updated_at=now()
			WHERE device_id=$1 AND status IN ('pending','running')`, id); err != nil {
			return Device{}, err
		}
		if device.VoipmonitorEnabled {
			if _, err := tx.Exec(ctx, `INSERT INTO voipmonitor_match_jobs
				(device_id,policy_revision,kind,generation) VALUES($1,$2,'discover',1)
				ON CONFLICT (device_id,policy_revision,kind,
					(COALESCE(bucket_start, '-infinity'::timestamptz)))
				DO UPDATE SET
					generation=voipmonitor_match_jobs.generation+1,
					status='pending',next_attempt_at=now(),completed_at=NULL,
					last_error=NULL,updated_at=now()`,
				id, revision); err != nil {
				return Device{}, err
			}
		}
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
