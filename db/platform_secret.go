package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// platformSecretID is the only row platform_secret ever holds. The id is pinned
// by a CHECK so a stray second key cannot be inserted and then ignored.
const platformSecretID = 1

// sealTransitionWindow 是签名根密钥轮换后「新旧都可解」的过渡期长度。
// 过渡期内 openSealed 会用新根密钥解不开时再试 jwt_key_prev；一旦超过窗口，
// 旧密钥不再参与解封，1.6.0 的自检口径原样恢复——过渡期不是永久豁免。
const sealTransitionWindow = 72 * time.Hour

// SealTransitionActive 判断 rotated_at 标记的过渡期在 now 时是否仍然有效。
// rotated_at 为零值（从未轮换）意味着没有旧密钥窗口，直接返回 false。
// now 早于 rotated_at（节点间时钟漂移）时按「仍在窗口内」处理，避免因为几秒
// 时钟差把存量密封值误判成不可读。
func SealTransitionActive(rotatedAt, now time.Time) bool {
	if rotatedAt.IsZero() {
		return false
	}
	return now.Before(rotatedAt.Add(sealTransitionWindow))
}

// PlatformJWTKeys is the full signing-root material: the current key that signs
// and seals new values, the previous key kept only for the rotation transition,
// and the moment the rotation happened. prev is "" and rotatedAt is zero on a
// database that never rotated.
func (d *DB) PlatformJWTKeys() (current, prev string, rotatedAt time.Time, found bool, err error) {
	return d.PlatformJWTKeysContext(context.Background())
}

// PlatformJWTKeysContext is PlatformJWTKeys with cancellation.
func (d *DB) PlatformJWTKeysContext(ctx context.Context) (current, prev string, rotatedAt time.Time, found bool, err error) {
	var at sql.NullTime
	err = d.QueryRowContext(ctx, `SELECT jwt_key, jwt_key_prev, rotated_at FROM platform_secret WHERE id=$1`,
		platformSecretID).Scan(&current, &prev, &at)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", "", time.Time{}, false, nil
	case err != nil:
		return "", "", time.Time{}, false, err
	}
	if at.Valid {
		rotatedAt = at.Time
	}
	return current, prev, rotatedAt, true, nil
}

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
//
// 关键：INSERT 只写 (id, jwt_key)，ON CONFLICT DO NOTHING 对既有行不碰 jwt_key_prev
// 与 rotated_at——轮换过的库重启后走的就是这条冲突分支，旧密钥窗口必须原样保留。
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

// RotatePlatformJWTKey atomically moves the current signing root into jwt_key_prev,
// installs candidate as the new root and stamps rotated_at to open the transition
// window. It is a no-op when candidate already is the current key, so a repeated
// rotation request cannot erase a window that is still needed.
//
// 返回被替换下来的旧密钥，调用方据此让进程内的密封层进入双密钥过渡期；若库里
// 还没有任何密钥，先按首次启动写入 candidate 再返回空旧密钥（没有存量需要兼容）。
func (d *DB) RotatePlatformJWTKey(candidate string) (prev string, err error) {
	return d.RotatePlatformJWTKeyContext(context.Background(), candidate)
}

// RotatePlatformJWTKeyContext is RotatePlatformJWTKey with cancellation.
func (d *DB) RotatePlatformJWTKeyContext(ctx context.Context, candidate string) (prev string, err error) {
	if len(candidate) < 32 {
		return "", errors.New("签名密钥至少 32 字节")
	}
	err = d.QueryRowContext(ctx, `
		WITH rotated AS (
			UPDATE platform_secret
			   SET jwt_key_prev = jwt_key, jwt_key = $1, rotated_at = now()
			 WHERE id = $2 AND jwt_key <> $1
			RETURNING jwt_key_prev
		)
		SELECT jwt_key_prev FROM rotated
		UNION ALL
		SELECT '' FROM platform_secret WHERE id = $2 AND jwt_key = $1
		LIMIT 1`, candidate, platformSecretID).Scan(&prev)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// No row yet: first boot, adopt candidate and start with no old key.
		final, e := d.EnsurePlatformJWTKeyContext(ctx, candidate)
		if e != nil {
			return "", fmt.Errorf("写入首个签名密钥: %w", e)
		}
		if final != candidate {
			return "", errors.New("签名密钥已被其他实例写入，请重读后再轮换")
		}
		return "", nil
	case err != nil:
		return "", err
	}
	return prev, nil
}
