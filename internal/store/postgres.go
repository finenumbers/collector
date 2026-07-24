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
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/argon2"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	DB *pgxpool.Pool
}

type User struct {
	ID       uuid.UUID `json:"id"`
	Username string    `json:"username"`
	Role     string    `json:"role"`
}

type Device struct {
	ID                uuid.UUID       `json:"id"`
	Name              string          `json:"name"`
	Model             string          `json:"model"`
	Firmware          string          `json:"firmware"`
	Timezone          string          `json:"timezone"`
	ManagementIP      *string         `json:"managementIp,omitempty"`
	SyslogSourceIP    string          `json:"syslogSourceIp"`
	DeviceSign        string          `json:"deviceSign"`
	AntifraudEnabled  bool            `json:"antifraudEnabled"`
	AntifraudMode     string          `json:"antifraudMode"`
	FTPUsername       string          `json:"ftpUsername"`
	FTPHome           string          `json:"ftpHome"`
	CDRColumns        json.RawMessage `json:"cdrColumns"`
	Enabled           bool            `json:"enabled"`
	CreatedAt         time.Time       `json:"createdAt"`
	GeneratedPassword string          `json:"generatedPassword,omitempty"`
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
	Name             string `json:"name"`
	Firmware         string `json:"firmware"`
	Timezone         string `json:"timezone"`
	ManagementIP     string `json:"managementIp"`
	SyslogSourceIP   string `json:"syslogSourceIp"`
	DeviceSign       string `json:"deviceSign"`
	AntifraudEnabled bool   `json:"antifraudEnabled"`
	AntifraudMode    string `json:"antifraudMode"`
	Enabled          bool   `json:"enabled"`
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
	session.CSRF = csrf
	return session, nil
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	hash := sha256.Sum256([]byte(token))
	_, err := s.DB.Exec(ctx, `DELETE FROM sessions WHERE id_hash=$1`, hash[:])
	return err
}

func (s *Store) ListDevices(ctx context.Context) ([]Device, error) {
	rows, err := s.DB.Query(ctx, `SELECT id,name,model,firmware,timezone,management_ip::text,
		syslog_source_ip::text,COALESCE(device_sign,''),antifraud_enabled,antifraud_mode,
		ftp_username,ftp_home,cdr_columns,enabled,created_at FROM devices ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Device
	for rows.Next() {
		var device Device
		if err := rows.Scan(&device.ID, &device.Name, &device.Model, &device.Firmware, &device.Timezone,
			&device.ManagementIP, &device.SyslogSourceIP, &device.DeviceSign, &device.AntifraudEnabled,
			&device.AntifraudMode, &device.FTPUsername, &device.FTPHome, &device.CDRColumns,
			&device.Enabled, &device.CreatedAt); err != nil {
			return nil, err
		}
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
) (uuid.UUID, string, error) {
	var id uuid.UUID
	var timezone string
	err := s.DB.QueryRow(ctx,
		`SELECT id,timezone FROM devices WHERE syslog_source_ip=$1 AND enabled`, sourceIP).
		Scan(&id, &timezone)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", ErrNotFound
	}
	return id, timezone, err
}

func (s *Store) Device(ctx context.Context, id uuid.UUID) (Device, error) {
	var device Device
	err := s.DB.QueryRow(ctx, `SELECT id,name,model,firmware,timezone,management_ip::text,
		syslog_source_ip::text,COALESCE(device_sign,''),antifraud_enabled,antifraud_mode,
		ftp_username,ftp_home,cdr_columns,enabled,created_at FROM devices WHERE id=$1`, id).
		Scan(&device.ID, &device.Name, &device.Model, &device.Firmware, &device.Timezone,
			&device.ManagementIP, &device.SyslogSourceIP, &device.DeviceSign, &device.AntifraudEnabled,
			&device.AntifraudMode, &device.FTPUsername, &device.FTPHome, &device.CDRColumns,
			&device.Enabled, &device.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	return device, err
}

func (s *Store) DeviceTimezone(ctx context.Context, id uuid.UUID) (string, error) {
	var timezone string
	err := s.DB.QueryRow(ctx, `SELECT timezone FROM devices WHERE id=$1`, id).Scan(&timezone)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return timezone, err
}

func (s *Store) RegisterIngestFile(ctx context.Context, deviceID uuid.UUID, name, objectKey, checksum string, size int64) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.DB.QueryRow(ctx, `INSERT INTO ingest_files(device_id,original_name,object_key,sha256,size_bytes,status)
		VALUES($1,$2,$3,$4,$5,'received') ON CONFLICT(device_id,sha256) DO NOTHING RETURNING id`,
		deviceID, name, objectKey, checksum, size).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	return id, err
}

func (s *Store) CompleteIngestFile(ctx context.Context, id uuid.UUID, status string, rowsTotal, rowsValid uint64, message string) error {
	_, err := s.DB.Exec(ctx, `UPDATE ingest_files SET status=$2,rows_total=$3,rows_valid=$4,
		error=NULLIF($5,''),processed_at=now() WHERE id=$1`, id, status, rowsTotal, rowsValid, message)
	return err
}

func (s *Store) CreateDevice(ctx context.Context, input NewDevice, actor User, remoteIP string) (Device, error) {
	if strings.TrimSpace(input.Name) == "" || net.ParseIP(input.SyslogSourceIP) == nil {
		return Device{}, errors.New("name and valid syslogSourceIp are required")
	}
	if input.Model == "" {
		input.Model = "SMG-1016M"
	}
	if input.Firmware == "" {
		input.Firmware = "3.410.0.7443"
	}
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
		(id,name,model,firmware,timezone,management_ip,syslog_source_ip,device_sign,
		 antifraud_enabled,antifraud_mode,ftp_username,ftp_home,cdr_columns)
		VALUES($1,$2,$3,$4,$5,NULLIF($6,'')::inet,$7,$8,$9,$10,$11,$12,$13)
		RETURNING id,name,model,firmware,timezone,management_ip::text,syslog_source_ip::text,
		 COALESCE(device_sign,''),antifraud_enabled,antifraud_mode,ftp_username,ftp_home,
		 cdr_columns,enabled,created_at`,
		id, strings.TrimSpace(input.Name), input.Model, input.Firmware, input.Timezone,
		input.ManagementIP, input.SyslogSourceIP, input.DeviceSign, input.AntifraudEnabled,
		input.AntifraudMode, ftpUsername, ftpHome, columns,
	).Scan(&device.ID, &device.Name, &device.Model, &device.Firmware, &device.Timezone,
		&device.ManagementIP, &device.SyslogSourceIP, &device.DeviceSign, &device.AntifraudEnabled,
		&device.AntifraudMode, &device.FTPUsername, &device.FTPHome, &device.CDRColumns,
		&device.Enabled, &device.CreatedAt)
	if err != nil {
		return Device{}, err
	}
	details, _ := json.Marshal(map[string]any{"name": device.Name, "syslogSourceIp": device.SyslogSourceIP})
	_, err = tx.Exec(ctx, `INSERT INTO audit_log(actor_id,action,resource_type,resource_id,remote_ip,details)
		VALUES($1,'device_create','device',$2,$3,$4)`, actor.ID, id.String(), nullableIP(remoteIP), details)
	if err != nil {
		return Device{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Device{}, err
	}
	device.GeneratedPassword = ftpPassword
	return device, nil
}

func (s *Store) UpdateDevice(
	ctx context.Context, id uuid.UUID, input DeviceUpdate, actor User, remoteIP string,
) (Device, error) {
	if strings.TrimSpace(input.Name) == "" || net.ParseIP(input.SyslogSourceIP) == nil {
		return Device{}, errors.New("name and valid syslogSourceIp are required")
	}
	if _, err := time.LoadLocation(input.Timezone); err != nil {
		return Device{}, fmt.Errorf("invalid IANA timezone %q", input.Timezone)
	}
	if input.ManagementIP != "" && net.ParseIP(input.ManagementIP) == nil {
		return Device{}, errors.New("managementIp must be empty or a valid IP")
	}
	if input.Firmware == "" {
		return Device{}, errors.New("firmware is required")
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return Device{}, err
	}
	defer tx.Rollback(ctx)
	var device Device
	err = tx.QueryRow(ctx, `UPDATE devices SET
		name=$2,firmware=$3,timezone=$4,management_ip=NULLIF($5,'')::inet,
		syslog_source_ip=$6,device_sign=$7,antifraud_enabled=$8,antifraud_mode=$9,
		enabled=$10
		WHERE id=$1
		RETURNING id,name,model,firmware,timezone,management_ip::text,syslog_source_ip::text,
			COALESCE(device_sign,''),antifraud_enabled,antifraud_mode,ftp_username,ftp_home,
			cdr_columns,enabled,created_at`,
		id, strings.TrimSpace(input.Name), input.Firmware, input.Timezone,
		input.ManagementIP, input.SyslogSourceIP, input.DeviceSign,
		input.AntifraudEnabled, input.AntifraudMode, input.Enabled,
	).Scan(&device.ID, &device.Name, &device.Model, &device.Firmware, &device.Timezone,
		&device.ManagementIP, &device.SyslogSourceIP, &device.DeviceSign,
		&device.AntifraudEnabled, &device.AntifraudMode, &device.FTPUsername,
		&device.FTPHome, &device.CDRColumns, &device.Enabled, &device.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	if err != nil {
		return Device{}, err
	}
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
	return device, tx.Commit(ctx)
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
	return tx.Commit(ctx)
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
