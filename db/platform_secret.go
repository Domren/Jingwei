package db

import (
	"context"
	"database/sql"
	"errors"
)

// platformSecretID is the only row platform_secret ever holds. The id is pinned
// by a CHECK so a stray second key cannot be inserted and then ignored.
const platformSecretID = 1

// PlatformJWTKey returns the platform signing root. ok=false means no row yet,
// which is a normal first boot rather than an error.
func (d *DB) PlatformJWTKey() (string, bool, error) {
	return d.PlatformJWTKeyContext(context.Background())
}

// PlatformJWTKeyContext is PlatformJWTKey with cancellation.
func (d *DB) PlatformJWTKeyContext(ctx context.Context) (string, bool, error) {
	var value string
	err := d.QueryRowContext(ctx, `SELECT jwt_key FROM platform_secret WHERE id=$1`, platformSecretID).Scan(&value)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", false, nil
	case err != nil:
		return "", false, err
	}
	return value, true, nil
}

// EnsurePlatformJWTKey stores candidate unless the database already holds a key,
// and returns the key the database actually ends up holding. The decision is made
// by the primary-key constraint rather than by a read the caller did first, so two
// instances booting against the same database converge on one signing key instead
// of each minting its own and bricking the other's shells.
func (d *DB) EnsurePlatformJWTKey(candidate string) (string, error) {
	return d.EnsurePlatformJWTKeyContext(context.Background(), candidate)
}

// EnsurePlatformJWTKeyContext is EnsurePlatformJWTKey with cancellation.
func (d *DB) EnsurePlatformJWTKeyContext(ctx context.Context, candidate string) (string, error) {
	if len(candidate) < 32 {
		return "", errors.New("签名密钥至少 32 字节")
	}
	var stored string
	err := d.QueryRowContext(ctx, `
		WITH inserted AS (
			INSERT INTO platform_secret(id, jwt_key) VALUES ($2, $1)
			ON CONFLICT (id) DO NOTHING
			RETURNING jwt_key
		)
		SELECT jwt_key FROM inserted
		UNION ALL
		SELECT jwt_key FROM platform_secret WHERE id = $2
		LIMIT 1`, candidate, platformSecretID).Scan(&stored)
	if err != nil {
		return "", err
	}
	return stored, nil
}
