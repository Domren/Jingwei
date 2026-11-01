package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtKeyFilename = "jwt.key"
	authPassKey    = "auth.password_hash"
	authTokenVer   = "auth.token_version"
	authCookieName = "jingwei_token"
	authUsername   = "Jingwei"
	// 24 hours instead of the previous 7 days. Password changes rotate the
	// token version and revoke every older session immediately; the shorter TTL
	// bounds the window for a cookie stolen by other means.
	jwtTTL   = 24 * time.Hour
	keyChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// 下限与 setup 页的前端校验一致——校验只放在前端等于没放，直接打 API 就能
	// 绕过。上限是 bcrypt 的硬限制：超过 72 字节 GenerateFromPassword 会返回
	// ErrPasswordTooLong，提前挡掉好过让用户收到一句含义不明的「密码加密失败」。
	minPasswordRunes = 8
	maxPasswordBytes = 72
)

// errDataSourceUnavailable 是密码相关读操作失败时统一的回复。这些 handler 绝不能
// 把"读不到"当成"没有设置"：authInit 曾因此在数据库报错时放行，让未认证请求覆盖
// 掉已有的管理员密码。
const errDataSourceUnavailable = "数据源暂时不可用，请稍后重试"

// errInvalidAuthToken distinguishes a bad/revoked token (401) from a database
// outage while looking up the token version (503).
var errInvalidAuthToken = errors.New("invalid auth token")

// validatePassword 返回空串表示通过，否则返回可直接展示给用户的中文原因。
func validatePassword(pw string) string {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return fmt.Sprintf("密码长度至少 %d 位", minPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Sprintf("密码长度不能超过 %d 字节", maxPasswordBytes)
	}
	return ""
}

// loadOrCreateJWTKey reads the 32-byte signing key from keyDir/jwt.key. keyDir is
// the project base dir (next to the executable), NOT the browsable workspace root
// (dataDir) — the signing key must never be listable/downloadable via the file
// manager. Legacy installs kept it at dataDir/jwt.key; if present there and not yet
// at the new location, it is migrated (key preserved, so sessions stay valid) and
// the old file removed so it disappears from the workspace. On first run a random
// key is generated and persisted.
func loadOrCreateJWTKey(keyDir, dataDir string) ([]byte, error) {
	path := filepath.Join(keyDir, jwtKeyFilename)
	// one-time migration out of the old in-workspace location.
	if legacy := filepath.Join(dataDir, jwtKeyFilename); legacy != path {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if data, rerr := os.ReadFile(legacy); rerr == nil {
				if werr := os.WriteFile(path, data, 0o600); werr == nil {
					_ = os.Remove(legacy)
					log.Printf("[auth] JWT key 已从 %s 迁移到 %s（移出可浏览工作区）", legacy, path)
				}
			}
		}
	}
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return []byte(strings.TrimSpace(string(data))), nil
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] 新 JWT key 已写入 %s", path)
	return buf, nil
}

type authSessionClaims struct {
	// Version is compared with the server-side auth.token_version. Rotating that
	// value on every password change invalidates all previously issued tokens.
	Version string `json:"ver"`
	jwt.RegisteredClaims
}

func parseJWT(tokenStr string, key []byte, claims jwt.Claims) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return key, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithExpirationRequired())
}

// signJWT issues a 24-hour HS256 token bound to the given token version.
func signJWT(key []byte, version string) (string, error) {
	now := time.Now()
	return jwt.NewWithClaims(jwt.SigningMethodHS256, authSessionClaims{
		Version: version,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   authUsername,
			ExpiresAt: jwt.NewNumericDate(now.Add(jwtTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}).SignedString(key)
}

// verifyJWT only checks the signature and expiry. Authentication paths must use
// verifySessionJWT, which also enforces the revocable token version.
func verifyJWT(tokenStr string, key []byte) bool {
	t, err := parseJWT(tokenStr, key, &jwt.RegisteredClaims{})
	return err == nil && t.Valid
}

func verifySessionJWT(tokenStr string, key []byte, version string) bool {
	if version == "" || tokenStr == "" {
		return false
	}
	claims := &authSessionClaims{}
	t, err := parseJWT(tokenStr, key, claims)
	if err != nil || !t.Valid || claims.Subject != authUsername {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(claims.Version), []byte(version)) == 1
}

// extractToken accepts the Authorization header (CLI/automation) and the
// HttpOnly session cookie (browsers). A token is never accepted from the query
// string: URLs end up in proxy logs, browser history and Referer headers.
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	if c, err := r.Cookie(authCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	return ""
}

func authCookieSecure(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (s *Server) setAuthCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   authCookieSecure(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(jwtTTL.Seconds()),
		Expires:  time.Now().Add(jwtTTL),
	})
}

func (s *Server) clearAuthCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   authCookieSecure(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	})
}

func (s *Server) setAuthVersion(version string) {
	s.authVerMu.Lock()
	s.authVer = version
	s.authVerMu.Unlock()
}

// ensureAuthTokenVersion returns the current token version, creating one on
// first use (including the first request after upgrading from 1.3.0). Creating
// it lazily on an existing installation immediately invalidates all legacy
// tokens, which had no version claim.
func (s *Server) ensureAuthTokenVersion() (string, error) {
	s.authVerMu.RLock()
	if s.authVer != "" {
		v := s.authVer
		s.authVerMu.RUnlock()
		return v, nil
	}
	s.authVerMu.RUnlock()

	s.authVerMu.Lock()
	defer s.authVerMu.Unlock()
	if s.authVer != "" {
		return s.authVer, nil
	}
	if s.m == nil || s.m.pg == nil {
		return "", errors.New(errDataSourceUnavailable)
	}
	pg := s.m.pg
	if v, ok, err := pg.GetSetting(authTokenVer); err != nil {
		return "", err
	} else if ok && v != "" {
		s.authVer = v
		return v, nil
	}
	version, err := randomHex(24)
	if err != nil {
		return "", err
	}
	if _, err := pg.InsertSettingIfAbsent(authTokenVer, version); err != nil {
		return "", err
	}
	// Another process may have won the insert race; the stored value is the
	// single source of truth.
	stored, ok, err := pg.GetSetting(authTokenVer)
	if err != nil {
		return "", err
	}
	if !ok || stored == "" {
		return "", errors.New("token version unavailable")
	}
	s.authVer = stored
	return stored, nil
}

func (s *Server) authenticateToken(token string) error {
	if token == "" {
		return errInvalidAuthToken
	}
	version, err := s.ensureAuthTokenVersion()
	if err != nil {
		return err
	}
	if !verifySessionJWT(token, s.jwtKey, version) {
		return errInvalidAuthToken
	}
	return nil
}

func (s *Server) validSession(r *http.Request) error {
	return s.authenticateToken(extractToken(r))
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
}

// requireAuth wraps h with JWT validation.
// /api/auth/*, /api/health and the Basic Auth gate check are exempt.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || p == "/api/health" || p == "/api/basic-auth/check" {
			h.ServeHTTP(w, r)
			return
		}
		if err := s.validSession(r); err != nil {
			if errors.Is(err, errInvalidAuthToken) {
				if _, cerr := r.Cookie(authCookieName); cerr == nil {
					s.clearAuthCookie(w, r)
				}
				writeErr(w, 401, "token 无效、已过期或已被吊销")
			} else {
				writeErr(w, 503, errDataSourceUnavailable)
			}
			return
		}
		// Authenticated API responses must never be reused by a shared cache.
		noStore(w)
		w.Header().Add("Vary", "Cookie")
		w.Header().Add("Vary", "Authorization")
		h.ServeHTTP(w, r)
	})
}

func authErrorStatus(err error) int {
	if errors.Is(err, errInvalidAuthToken) {
		return 401
	}
	return 503
}

// GET /api/auth/status — reports whether the admin password has been initialised.
// 读失败必须回 503 而不是 initialized:false：前端在 initialized:false 时会把用户
// 送到 /setup 去设置密码（login/page.tsx），把数据库故障包装成 200 等于把用户往
// 覆盖已有密码的路上推。
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	pg := s.pg(w)
	if pg == nil {
		return
	}
	hash, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"initialized": hash != ""})
}

// GET /api/auth/session — lets the cookie-based frontend confirm its session
// without reading an HttpOnly token. An invalid cookie is cleared here so the
// Next.js page gate cannot bounce between /login and the main UI.
func (s *Server) authSession(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if err := s.validSession(r); err != nil {
		if errors.Is(err, errInvalidAuthToken) {
			s.clearAuthCookie(w, r)
			writeErr(w, 401, "未登录或会话已失效")
			return
		}
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"authenticated": true, "username": authUsername})
}

// POST /api/auth/logout — clears the session cookie. Logout is intentionally not
// a token-version rotation: that would sign out every browser, which is not what
// a single-device logout promises. Password changes provide global revocation.
func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	s.clearAuthCookie(w, r)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/auth/init — sets the password for the first time; rejected if already set.
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	pg := s.pg(w)
	if pg == nil {
		return
	}
	// Read before decoding the body: a database outage must still fail closed
	// even if the caller sent no usable captcha.
	existing, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if existing != "" {
		writeErr(w, 403, "密码已设置")
		return
	}
	prepareAuthRequest(w, r)
	var req struct {
		Password  string `json:"password"`
		CaptchaID string `json:"captcha_id"`
		CaptchaX  int    `json:"captcha_x"`
	}
	if err := decode(r, &req); err != nil {
		writeAuthDecodeError(w, err)
		return
	}
	if req.Password == "" {
		writeErr(w, 400, "密码不能为空")
		return
	}
	ip := clientIP(r)
	if !validateCaptcha(s, r, req.CaptchaID, req.CaptchaX) {
		writeErr(w, 400, "滑块验证失败或已过期，请刷新后重试")
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	version, err := randomHex(24)
	if err != nil {
		writeErr(w, 500, "会话初始化失败")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	tx, err := pg.BeginTx(ctx, nil)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit
	// 用 INSERT ... ON CONFLICT DO NOTHING 而不是 upsert：上面那次 GetSetting 只是
	// 快速失败路径，真正"仅首次可设"的保证落在主键约束上。bcrypt 要跑几十毫秒，
	// 这期间别的请求完全可能先把密码设好，而读检查本身也可能因故障而失效。
	res, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT (key) DO NOTHING`, authPassKey, string(hash))
	if err != nil {
		log.Printf("[auth] 初始化密码写入失败: %v", err)
		writeErr(w, 503, "保存失败，请重试")
		return
	}
	affected, err := res.RowsAffected()
	if err != nil {
		writeErr(w, 503, "保存失败，请重试")
		return
	}
	if affected == 0 {
		writeErr(w, 403, "密码已设置")
		return
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES($1,$2)
ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, authTokenVer, version); err != nil {
		log.Printf("[auth] 初始化 token 版本失败: %v", err)
		writeErr(w, 503, "保存失败，请重试")
		return
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, 503, "保存失败，请重试")
		return
	}
	s.setAuthVersion(version)
	tok, err := signJWT(s.jwtKey, version)
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	s.setAuthCookie(w, r, tok)
	log.Printf("[auth] 管理员密码已初始化 ip=%s（已签发新会话）", ip)
	writeJSON(w, 200, map[string]any{"ok": true, "token": tok, "expires_in": int(jwtTTL.Seconds())})
}

// POST /api/auth/change-password — changes the admin password. Requires a valid
// session AND the current password. The password hash and token version are
// committed in one transaction; every session except the one that receives the
// replacement cookie stops working immediately.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if err := s.validSession(r); err != nil {
		if errors.Is(err, errInvalidAuthToken) {
			writeErr(w, 401, "未授权")
		} else {
			writeErr(w, 503, errDataSourceUnavailable)
		}
		return
	}
	prepareAuthRequest(w, r)
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(r, &req); err != nil {
		writeAuthDecodeError(w, err)
		return
	}
	if req.NewPassword == "" {
		writeErr(w, 400, "新密码不能为空")
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "密码未初始化，请先设置密码")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)); err != nil {
		writeErr(w, 401, "当前密码错误")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	version, err := randomHex(24)
	if err != nil {
		writeErr(w, 500, "会话更新失败")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	tx, err := pg.BeginTx(ctx, nil)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit
	if _, err := tx.ExecContext(ctx, `UPDATE settings SET value=$2, updated_at=now() WHERE key=$1`, authPassKey, string(newHash)); err != nil {
		log.Printf("[auth] 更新密码失败: %v", err)
		writeErr(w, 503, "保存失败，请重试")
		return
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES($1,$2)
ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, authTokenVer, version); err != nil {
		log.Printf("[auth] 更新 token 版本失败: %v", err)
		writeErr(w, 503, "保存失败，请重试")
		return
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, 503, "保存失败，请重试")
		return
	}
	s.setAuthVersion(version)
	tok, err := signJWT(s.jwtKey, version)
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	s.setAuthCookie(w, r, tok)
	ip := clientIP(r)
	s.loginLimiter.success(ip)
	log.Printf("[auth] 管理员密码已修改 ip=%s，全部旧会话已吊销", ip)
	writeJSON(w, 200, map[string]any{"ok": true, "token": tok, "expires_in": int(jwtTTL.Seconds())})
}

// POST /api/auth/login — validates captcha + username/password, sets an HttpOnly
// session cookie and (for CLI/automation) returns the bearer token.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ip := clientIP(r)
	if wait := s.loginLimiter.lockedFor(ip); wait > 0 {
		writeRateLimited(w, wait, "登录失败次数过多，请稍后重试")
		return
	}
	prepareAuthRequest(w, r)
	var req struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		CaptchaID string `json:"captcha_id"`
		CaptchaX  int    `json:"captcha_x"`
	}
	if err := decode(r, &req); err != nil {
		writeAuthDecodeError(w, err)
		return
	}
	if req.CaptchaID == "" {
		writeErr(w, 400, "请先完成滑块验证")
		return
	}
	if !validateCaptcha(s, r, req.CaptchaID, req.CaptchaX) {
		log.Printf("[auth] 登录验证码失败 ip=%s", ip)
		writeErr(w, 400, "滑块验证失败或已过期，请刷新后重试")
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "密码未初始化，请先设置密码")
		return
	}
	// Compare even when the username is wrong so an unknown username does not
	// answer measurably faster than a wrong password.
	passwordOK := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) == nil
	if req.Username != authUsername || !passwordOK {
		if wait := s.loginLimiter.fail(ip); wait > 0 {
			log.Printf("[auth] 登录锁定 ip=%s 持续=%s", ip, wait)
			writeRateLimited(w, wait, "登录失败次数过多，请稍后重试")
			return
		}
		log.Printf("[auth] 登录失败 ip=%s（用户名或密码错误）", ip)
		writeErr(w, 401, "用户名或密码错误")
		return
	}
	version, err := s.ensureAuthTokenVersion()
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	tok, err := signJWT(s.jwtKey, version)
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	s.loginLimiter.success(ip)
	s.setAuthCookie(w, r, tok)
	log.Printf("[auth] 登录成功 ip=%s", ip)
	writeJSON(w, 200, map[string]any{"ok": true, "token": tok, "expires_in": int(jwtTTL.Seconds())})
}
