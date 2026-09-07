package users

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"kptv-proxy/work/constants"
	"kptv-proxy/work/db"
	"kptv-proxy/work/logger"
	"time"
)

// Session holds the data for an authenticated session.
type Session struct {
	UserID    int64
	Username  string
	Name      string
	ExpiresAt time.Time
}

func init() {
	go sessionCleanup()
}

// hashSessionID returns the hex-encoded SHA-256 of a raw session ID. IDs are 64
// characters of crypto/rand output, so a KDF is unnecessary and a fast hash
// allows an indexed single-row lookup. Only the hash is stored, so a database
// copy cannot be replayed as a live session.
func hashSessionID(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// CreateSession generates a new session for a user and returns the session ID.
func CreateSession(userID int64, username, name string, rememberMe bool) (string, error) {
	id, err := generateSessionID()
	if err != nil {
		return "", err
	}

	ttl := constants.Internal.SessionTTL
	if rememberMe {
		ttl = constants.Internal.SessionTTLExtended
	}

	_, err = db.Get().Exec(`
		INSERT INTO kp_sessions (id_hash, user_id, username, name, expires_at)
		VALUES (?, ?, ?, ?, ?)`,
		hashSessionID(id), userID, username, name, time.Now().Add(ttl).Unix(),
	)
	if err != nil {
		logger.Error("{users/session - CreateSession} %v", err)
		return "", err
	}

	return id, nil
}

// GetSession retrieves a session by ID, returning nil if not found or expired.
// An expired row is deleted on read rather than waiting for the cleanup tick.
func GetSession(id string) *Session {
	var (
		s         Session
		expiresAt int64
	)

	err := db.GetReader().QueryRow(`
		SELECT user_id, username, name, expires_at
		FROM kp_sessions WHERE id_hash = ?`, hashSessionID(id),
	).Scan(&s.UserID, &s.Username, &s.Name, &expiresAt)
	if err != nil {
		if err != sql.ErrNoRows {
			logger.Error("{users/session - GetSession} %v", err)
		}
		return nil
	}

	s.ExpiresAt = time.Unix(expiresAt, 0)
	if time.Now().After(s.ExpiresAt) {
		DeleteSession(id)
		return nil
	}
	return &s
}

// DeleteSession removes a session by ID.
func DeleteSession(id string) {
	if _, err := db.Get().Exec(`DELETE FROM kp_sessions WHERE id_hash = ?`, hashSessionID(id)); err != nil {
		logger.Error("{users/session - DeleteSession} %v", err)
	}
}

// DeleteSessionsForUser revokes every outstanding session belonging to a user.
func DeleteSessionsForUser(userID int64) {
	if _, err := db.Get().Exec(`DELETE FROM kp_sessions WHERE user_id = ?`, userID); err != nil {
		logger.Error("{users/session - DeleteSessionsForUser} id=%d: %v", userID, err)
	}
}

// sessionCleanup periodically removes expired sessions.
func sessionCleanup() {
	ticker := time.NewTicker(constants.Internal.SessionCleanupTick)
	defer ticker.Stop()
	for range ticker.C {
		if _, err := db.Get().Exec(`DELETE FROM kp_sessions WHERE expires_at <= ?`, time.Now().Unix()); err != nil {
			logger.Error("{users/session - sessionCleanup} %v", err)
		}
	}
}

// generateSessionID creates a cryptographically secure 64-character session ID.
func generateSessionID() (string, error) {
	s, err := randomAlnum(64)
	if err != nil {
		return "", fmt.Errorf("generating session ID: %w", err)
	}
	return s, nil
}
