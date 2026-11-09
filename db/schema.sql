-- ARTEX PostgreSQL schema (单一数据源)
-- 幂等：可重复执行（IF NOT EXISTS / OR REPLACE / DROP TRIGGER IF EXISTS）。

-- =====================================================================
-- 0. 通用：updated_at 触发器
-- =====================================================================
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

-- 安全的 text→inet 转换：非法值返回 NULL 而不是抛 22P02。assets.ip 是自由文本
-- (Agent / 资产 API 可能写进主机名)，裸转 a.ip::inet 会让单独一行脏数据把整条
-- 企业归属重算语句打挂。调用方用 try_inet(...) IS NULL 找出这些行并告警。
-- 不用 pg_input_is_valid 是因为那要 PG16+，这里要兼容更老的存量库。
CREATE OR REPLACE FUNCTION try_inet(value text) RETURNS inet AS $$
BEGIN
    RETURN value::inet;
EXCEPTION WHEN others THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql IMMUTABLE STRICT;

-- =====================================================================
-- A. 资产层：companies / assets / company_scope
-- =====================================================================

CREATE TABLE IF NOT EXISTS companies (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    nkey       TEXT NOT NULL UNIQUE,
    logo       TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_companies_nkey ON companies(nkey);
DROP TRIGGER IF EXISTS trg_companies_upd ON companies;
CREATE TRIGGER trg_companies_upd BEFORE UPDATE ON companies
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS assets (
    id              BIGSERIAL PRIMARY KEY,
    type            TEXT NOT NULL CHECK (type IN (
                        'root_domain','ip','subdomain','app','service','endpoint'
                    )),
    company_id      BIGINT REFERENCES companies(id) ON DELETE SET NULL,
    -- explicit: caller/user selected the company; scope: derived from company_scope.
    -- Existing installations are conservatively migrated as explicit so a scope
    -- rebuild can never erase a historical manual association.
    company_source  TEXT NOT NULL DEFAULT 'explicit'
                    CHECK (company_source IN ('explicit','scope')),
    task_ids        BIGINT[] NOT NULL DEFAULT '{}',
    domain          TEXT,
    root_domain     TEXT,
    ip              TEXT,
    c_segment       CIDR,
    port            INTEGER CHECK (port BETWEEN 1 AND 65535),
    icp             TEXT,
    bound_domains   TEXT[]  NOT NULL DEFAULT '{}',
    open_ports      JSONB[] NOT NULL DEFAULT '{}',
    record_type     TEXT,
    record_value    TEXT[],
    bundle_id       TEXT,
    app_name        TEXT,
    category        TEXT,
    app_description TEXT,
    app_icp         TEXT,
    url             TEXT,
    service_type    TEXT CHECK (service_type IN ('http','other')),
    service_name    TEXT,
    favicon_mmh3    TEXT,
    status_code     INTEGER,
    content_length  BIGINT,
    page_title      TEXT,
    technologies    TEXT[]  NOT NULL DEFAULT '{}',
    auth            JSONB[] NOT NULL DEFAULT '{}',
    method          TEXT,
    params          JSONB[] NOT NULL DEFAULT '{}',
    extra           JSONB   NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_root_domain  ON assets(domain) WHERE type = 'root_domain';
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_ip           ON assets(ip)     WHERE type = 'ip';
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_subdomain    ON assets(domain, COALESCE(record_type,'')) WHERE type = 'subdomain';
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_app_bundle   ON assets(bundle_id) WHERE type = 'app' AND bundle_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_app_name     ON assets(app_name)  WHERE type = 'app' AND bundle_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_service_http ON assets(url) WHERE type = 'service' AND service_type = 'http';
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_service_other
    ON assets(COALESCE(domain,''), COALESCE(ip,''), port, service_name) WHERE type = 'service' AND service_type = 'other';
CREATE UNIQUE INDEX IF NOT EXISTS uq_av2_endpoint     ON assets(url, method) WHERE type = 'endpoint';
CREATE INDEX IF NOT EXISTS idx_av2_company      ON assets(company_id)       WHERE company_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_av2_company_type ON assets(company_id, type) WHERE company_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_av2_task_ids     ON assets USING GIN(task_ids);
CREATE INDEX IF NOT EXISTS idx_av2_domain       ON assets(domain)      WHERE domain IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_av2_root_domain  ON assets(root_domain) WHERE root_domain IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_av2_ip           ON assets(ip)          WHERE ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_av2_c_segment    ON assets USING GIST(c_segment inet_ops) WHERE c_segment IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_av2_technologies ON assets USING GIN(technologies) WHERE type = 'service';
CREATE INDEX IF NOT EXISTS idx_av2_bound_domains ON assets USING GIN(bound_domains) WHERE type = 'ip';
CREATE INDEX IF NOT EXISTS idx_av2_open_ports   ON assets USING GIN(open_ports)    WHERE type = 'ip';
CREATE INDEX IF NOT EXISTS idx_av2_last_seen    ON assets(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_av2_type_seen    ON assets(type, last_seen DESC);
ALTER TABLE assets ADD COLUMN IF NOT EXISTS company_source TEXT;
UPDATE assets SET company_source = 'explicit' WHERE company_source IS NULL;
ALTER TABLE assets ALTER COLUMN company_source SET DEFAULT 'explicit';
ALTER TABLE assets ALTER COLUMN company_source SET NOT NULL;
ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_company_source_check;
ALTER TABLE assets ADD CONSTRAINT assets_company_source_check
    CHECK (company_source IN ('explicit','scope'));
DROP TRIGGER IF EXISTS trg_av2_upd ON assets;
CREATE TRIGGER trg_av2_upd BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS company_scope (
    id         BIGSERIAL PRIMARY KEY,
    company_id BIGINT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('domain','ip','cidr','icp','keyword')),
    domain     TEXT,
    net        CIDR,
    value      TEXT,
    raw        TEXT NOT NULL,
    reason     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_sv2_domain UNIQUE (company_id, domain),
    CONSTRAINT uq_sv2_net    UNIQUE (company_id, net),
    CONSTRAINT ck_company_scope_payload CHECK (
        (kind = 'domain' AND domain IS NOT NULL AND net IS NULL AND value IS NULL)
        OR (kind IN ('ip','cidr') AND domain IS NULL AND net IS NOT NULL AND value IS NULL)
        OR (kind IN ('icp','keyword') AND domain IS NULL AND net IS NULL AND value IS NOT NULL)
    )
);
-- Existing installations need the new text payload and expanded kind check.
ALTER TABLE company_scope ADD COLUMN IF NOT EXISTS value TEXT;
ALTER TABLE company_scope DROP CONSTRAINT IF EXISTS company_scope_kind_check;
ALTER TABLE company_scope ADD CONSTRAINT company_scope_kind_check
    CHECK (kind IN ('domain','ip','cidr','icp','keyword'));
ALTER TABLE company_scope DROP CONSTRAINT IF EXISTS ck_company_scope_payload;
ALTER TABLE company_scope ADD CONSTRAINT ck_company_scope_payload CHECK (
    (kind = 'domain' AND domain IS NOT NULL AND net IS NULL AND value IS NULL)
    OR (kind IN ('ip','cidr') AND domain IS NULL AND net IS NOT NULL AND value IS NULL)
    OR (kind IN ('icp','keyword') AND domain IS NULL AND net IS NULL AND value IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_sv2_domain  ON company_scope(domain)   WHERE kind = 'domain';
CREATE INDEX IF NOT EXISTS idx_sv2_net     ON company_scope USING GIST(net inet_ops) WHERE kind IN ('ip','cidr');
CREATE UNIQUE INDEX IF NOT EXISTS uq_sv2_value ON company_scope(company_id, kind, value) WHERE kind IN ('icp','keyword');
CREATE INDEX IF NOT EXISTS idx_sv2_icp ON company_scope(value) WHERE kind = 'icp';
CREATE INDEX IF NOT EXISTS idx_sv2_company ON company_scope(company_id);

-- =====================================================================
-- B. 推理探索层
-- =====================================================================
CREATE TABLE IF NOT EXISTS explorations (
    id          BIGSERIAL PRIMARY KEY,
    description TEXT,
    goal        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open'
                  CHECK (status IN ('open','achieved','failed')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- cold-digest (§2.3): per-task planner round counter — bumped once each time the
-- planner wakes and processes a round. Drives the ≥R cold-node debounce (measured in
-- this exploration's own rounds, not global node ids or wall-clock).
ALTER TABLE explorations ADD COLUMN IF NOT EXISTS round_no BIGINT NOT NULL DEFAULT 0;
DROP TRIGGER IF EXISTS trg_exp_upd ON explorations;
CREATE TRIGGER trg_exp_upd BEFORE UPDATE ON explorations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS exploration_nodes (
    id             BIGSERIAL PRIMARY KEY,
    exploration_id BIGINT NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    kind           TEXT NOT NULL,
    payload        JSONB NOT NULL DEFAULT '{}',
    priority       INT  NOT NULL DEFAULT 0,
    state          TEXT NOT NULL DEFAULT 'open',
    origin         TEXT,
    owner          TEXT,
    blocked_reason TEXT,
    delete_reason  TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at   TIMESTAMPTZ,
    CONSTRAINT ck_node_kind CHECK (kind IN ('begin','goal','intent','fact','finding','hint','digest')),
    CONSTRAINT ck_node_state CHECK (
        (kind='begin'   AND state IN ('open')) OR
        (kind='intent'  AND state IN ('open','running','paused','done','blocked','exhausted','stopped','deleted')) OR
        (kind='goal'    AND state IN ('open','met','abandoned')) OR
        (kind='fact'    AND state IN ('confirmed','dismissed','origin')) OR
        (kind='finding' AND state IN ('confirmed','dismissed')) OR
        (kind='hint'    AND state IN ('active','consumed')) OR
        (kind='digest'  AND state IN ('active','superseded'))
    )
);
ALTER TABLE exploration_nodes ADD COLUMN IF NOT EXISTS blocked_reason TEXT;
-- 意图假删除(soft delete):state='deleted' 时,delete_reason 记用户填写的删除原因。
ALTER TABLE exploration_nodes ADD COLUMN IF NOT EXISTS delete_reason TEXT;
-- cold-digest (§2.3/§5.3): content_version bumps on any change that could alter a
-- digest body (summary/state/confidence); cold_since_round stamps the planner round
-- a node most recently went from "has a live downstream branch" to none (NULL = hot).
ALTER TABLE exploration_nodes ADD COLUMN IF NOT EXISTS content_version  INT    NOT NULL DEFAULT 0;
ALTER TABLE exploration_nodes ADD COLUMN IF NOT EXISTS cold_since_round BIGINT;
-- ck_node_kind: existing installs predate the 'digest' kind — recreate to allow it.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid='exploration_nodes'::regclass
          AND conname='ck_node_kind'
          AND pg_get_constraintdef(oid) NOT LIKE '%digest%'
    ) THEN
        ALTER TABLE exploration_nodes DROP CONSTRAINT ck_node_kind;
        ALTER TABLE exploration_nodes ADD CONSTRAINT ck_node_kind
            CHECK (kind IN ('begin','goal','intent','fact','finding','hint','digest'));
    END IF;
END $$;
-- ck_node_state: recreate when it lacks the 'paused' (older), 'superseded' (digest rev),
-- or 'deleted' (intent soft-delete rev) branches.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid='exploration_nodes'::regclass
          AND conname='ck_node_state'
          AND (pg_get_constraintdef(oid) NOT LIKE '%paused%'
               OR pg_get_constraintdef(oid) NOT LIKE '%superseded%'
               OR pg_get_constraintdef(oid) NOT LIKE '%deleted%')
    ) THEN
        ALTER TABLE exploration_nodes DROP CONSTRAINT ck_node_state;
        ALTER TABLE exploration_nodes ADD CONSTRAINT ck_node_state CHECK (
            (kind='begin'   AND state IN ('open')) OR
            (kind='intent'  AND state IN ('open','running','paused','done','blocked','exhausted','stopped','deleted')) OR
            (kind='goal'    AND state IN ('open','met','abandoned')) OR
            (kind='fact'    AND state IN ('confirmed','dismissed','origin')) OR
            (kind='finding' AND state IN ('confirmed','dismissed')) OR
            (kind='hint'    AND state IN ('active','consumed')) OR
            (kind='digest'  AND state IN ('active','superseded'))
        );
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_expnodes_part     ON exploration_nodes(exploration_id, kind);
CREATE INDEX IF NOT EXISTS idx_expnodes_frontier ON exploration_nodes(exploration_id, priority DESC)
    WHERE kind='intent' AND state='open';
DROP TRIGGER IF EXISTS trg_expnodes_upd ON exploration_nodes;
CREATE TRIGGER trg_expnodes_upd BEFORE UPDATE ON exploration_nodes
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS exploration_edges (
    exploration_id BIGINT NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    src_id         BIGINT NOT NULL REFERENCES exploration_nodes(id) ON DELETE CASCADE,
    dst_id         BIGINT NOT NULL REFERENCES exploration_nodes(id) ON DELETE CASCADE,
    rel            TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (exploration_id, src_id, rel, dst_id),
    CONSTRAINT ck_edge_noself CHECK (src_id <> dst_id),
    CONSTRAINT ck_edge_rel CHECK (rel IN ('spawns','derived_from','yields','proves','covers'))
);
CREATE INDEX IF NOT EXISTS idx_expedges_src ON exploration_edges(src_id, rel);
CREATE INDEX IF NOT EXISTS idx_expedges_dst ON exploration_edges(dst_id, rel);
-- cold-digest (§1): the 'covers' relation (digest→member) postdates shipped installs,
-- whose rel CHECK is an inline auto-named constraint. Find and recreate it as ck_edge_rel.
DO $$
DECLARE cname text;
BEGIN
    SELECT conname INTO cname FROM pg_constraint
     WHERE conrelid='exploration_edges'::regclass AND contype='c'
       AND pg_get_constraintdef(oid) LIKE '%rel%'
       AND pg_get_constraintdef(oid) NOT LIKE '%covers%';
    IF cname IS NOT NULL THEN
        EXECUTE 'ALTER TABLE exploration_edges DROP CONSTRAINT '||quote_ident(cname);
        ALTER TABLE exploration_edges ADD CONSTRAINT ck_edge_rel
            CHECK (rel IN ('spawns','derived_from','yields','proves','covers'));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS exploration_anchors (
    node_id   BIGINT NOT NULL REFERENCES exploration_nodes(id) ON DELETE CASCADE,
    asset_id  BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    PRIMARY KEY (node_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_anchor_asset ON exploration_anchors(asset_id);

-- task_constraints: operator-authored operation constraints (allow/deny) for a task.
-- Extracted by the goals decomposer at round 0 (from goal/description), editable at
-- runtime by the main agent + 总览「约束管理」. Injected into the planner/worker system
-- prompt each round (config-gated) to keep exploration within the operator's boundary.
CREATE TABLE IF NOT EXISTS task_constraints (
    id             BIGSERIAL PRIMARY KEY,
    exploration_id BIGINT NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    kind           TEXT NOT NULL CHECK (kind IN ('allow','deny')),
    text           TEXT NOT NULL,
    origin         TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_task_constraints_exp ON task_constraints(exploration_id);

CREATE TABLE IF NOT EXISTS activity (
    id                 BIGSERIAL PRIMARY KEY,
    exploration_id     BIGINT NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    node_id            BIGINT REFERENCES exploration_nodes(id) ON DELETE SET NULL,
    worker             TEXT,
    kind               TEXT,
    tool               TEXT,
    tool_use_id        TEXT,
    is_error           BOOLEAN NOT NULL DEFAULT false,
    summary            TEXT,
    detail             TEXT,
    metadata           JSONB NOT NULL DEFAULT '{}',
    input_tokens       INTEGER,
    output_tokens      INTEGER,
    cache_read_tokens  INTEGER,
    cache_write_tokens INTEGER,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE activity ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}';
-- main_seg segments the main-agent session into resettable conversations: a new
-- main session bumps the segment so its transcript + activity start clean while the
-- task's graph/assets/goal are untouched. NULL == legacy rows == segment 0 (the
-- original session). Only worker='mainagent' rows carry it.
ALTER TABLE activity ADD COLUMN IF NOT EXISTS main_seg INTEGER;
CREATE INDEX IF NOT EXISTS idx_act_node  ON activity(exploration_id, node_id, id);
CREATE INDEX IF NOT EXISTS idx_act_since ON activity(exploration_id, id);
CREATE INDEX IF NOT EXISTS idx_act_tool_call ON activity(exploration_id, tool_use_id, id)
  WHERE kind IN ('tool_use', 'tool_result');
-- Main/Plan history pages filter by worker (both carry NULL node_id, so idx_act_node
-- can't distinguish them); this covers reverse pagination of those sessions.
CREATE INDEX IF NOT EXISTS idx_act_worker ON activity(exploration_id, worker, id);
-- Main-session pages filter by segment on top of worker='mainagent'; this partial
-- index covers reverse pagination within one segment.
CREATE INDEX IF NOT EXISTS idx_act_main_seg ON activity(exploration_id, main_seg, id)
    WHERE worker='mainagent';
-- Task-list polls aggregate result usage and find the latest event repeatedly.
-- Cover the token columns for index-only aggregation and the timestamp order for
-- per-exploration latest-activity lookups.
CREATE INDEX IF NOT EXISTS idx_act_result_usage ON activity(exploration_id)
    INCLUDE (input_tokens, output_tokens, cache_read_tokens, cache_write_tokens)
    WHERE kind='result';
CREATE INDEX IF NOT EXISTS idx_act_latest ON activity(exploration_id, created_at DESC);

-- main_sessions records the resettable main-agent conversation segments of a task.
-- Segment 0 (the original session) is implicit and never stored; this table holds
-- only the extra segments created by "新建会话" (seq >= 1). The current segment is
-- MAX(seq) or 0. Each segment gets its own transcript file + activity slice; the
-- task's exploration graph/assets/goal are shared and never reset.
CREATE TABLE IF NOT EXISTS main_sessions (
    exploration_id BIGINT NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    seq            INTEGER NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (exploration_id, seq)
);

-- =====================================================================
-- C. LLM profiles
-- =====================================================================
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- platform_secret holds the platform signing root in exactly one row. Losing it
-- invalidates every login session and bricks every planted webshell, because
-- their stored keys are sealed with a derivation of it — so it belongs in the
-- database, the one artifact operators already dump before an upgrade, and not
-- in the container's writable layer where `compose up --force-recreate` used to
-- rotate it silently. It is deliberately NOT a settings row: settings are read
-- by name all over the app and echoed to the browser, while this value is
-- loaded exactly once, at startup.
CREATE TABLE IF NOT EXISTS platform_secret (
    id         SMALLINT PRIMARY KEY CHECK (id = 1),
    jwt_key    TEXT NOT NULL CHECK (char_length(jwt_key) >= 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS llm_profiles (
    id               BIGSERIAL PRIMARY KEY,
    name             TEXT NOT NULL UNIQUE,
    format           TEXT NOT NULL CHECK (format IN ('openai','anthropic','openai-responses')),
    base_url         TEXT,
    proxy            TEXT,
    model            TEXT NOT NULL,
    api_key          TEXT,
    api_key_hint     TEXT,
    rate_per_second  DOUBLE PRECISION NOT NULL DEFAULT 0,
    rate_per_minute  DOUBLE PRECISION NOT NULL DEFAULT 0,
    context_window_k INTEGER NOT NULL DEFAULT 0,
    -- 思考参数拆成两个独立字段：thinking_type=思考开关(''/disabled/enabled)，
    -- reasoning_effort=思考强度(''/low/medium/high/xhigh/max)，互不牵连。
    reasoning_effort TEXT NOT NULL DEFAULT '',
    thinking_type    TEXT NOT NULL DEFAULT '',
    is_default       BOOLEAN NOT NULL DEFAULT false,
    -- 轮询(故障转移)参数，见 docs/LLM轮询设计.md：
    --   priority     顺位，越大越先被选中；激活配置(is_default)永远排链首，与本值无关。
    --   pool_exclude true=不作为故障转移目标(仍可被 agent/任务显式绑定使用)。
    priority         INTEGER NOT NULL DEFAULT 0,
    pool_exclude     BOOLEAN NOT NULL DEFAULT false,
    -- streaming=true(默认)走流式 SSE；false 走真·非流式(stream:false，一次性 JSON)。
    streaming        BOOLEAN NOT NULL DEFAULT true,
    -- 单次回复的输出上限(token)。0=不发送该字段，由服务端默认值决定——保持既有行为。
    -- 与 context_window_k(模型总容量，仅本地用于压缩阈值)是两回事：本值会随请求发出。
    max_tokens       INTEGER NOT NULL DEFAULT 0,
    -- 输出上限用哪个请求字段名，仅对 format='openai' 生效：
    --   ''                      = max_tokens(默认，兼容绝大多数网关)
    --   'max_completion_tokens' = 新字段；OpenAI 推理模型(o 系列/GPT-5)只认它，
    --                             发 max_tokens 会被 unsupported_parameter 拒绝。
    -- anthropic(max_tokens 必填)与 openai-responses(max_output_tokens)自带字段名，不受此值影响。
    max_tokens_field TEXT NOT NULL DEFAULT '',
    -- 自定义会话头：非空时每次请求带一个该名字的 HTTP 头，头值=当前运行的 session id
    -- (chat 会话/worker 意图)。用于某些按 session-id 头做提示缓存/粘性路由的网关。''=不发送。
    session_header_key TEXT NOT NULL DEFAULT '',
    -- 重试覆盖：次数 0=用全局默认/-1=关闭/>0=该值；间隔 0=用默认指数退避/>0=固定毫秒。
    -- 三组分别对应建连重试、空响应重试、同 provider 安全窗口重试，详见下方 ALTER 处注释。
    retry_connect_attempts    INTEGER NOT NULL DEFAULT 0,
    retry_connect_interval_ms INTEGER NOT NULL DEFAULT 0,
    retry_empty_attempts      INTEGER NOT NULL DEFAULT 0,
    retry_empty_interval_ms   INTEGER NOT NULL DEFAULT 0,
    retry_stream_attempts     INTEGER NOT NULL DEFAULT 0,
    retry_stream_interval_ms  INTEGER NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_llm_one_default ON llm_profiles(is_default) WHERE is_default;
DROP TRIGGER IF EXISTS trg_llm_upd ON llm_profiles;
CREATE TRIGGER trg_llm_upd BEFORE UPDATE ON llm_profiles
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
-- 轮询顺位/排除标记；补旧库。默认 0 / false = 全部配置都参与轮询。
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS priority     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS pool_exclude BOOLEAN NOT NULL DEFAULT false;
-- 流式开关；补旧库。默认 true = 保持既有的流式行为，旧配置无感升级。
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS streaming    BOOLEAN NOT NULL DEFAULT true;
-- 放开 format 约束以容纳 openai-responses(OpenAI Responses API)；补旧库。
-- 每次启动执行,幂等:先删旧 CHECK 再建含三值的新 CHECK。
ALTER TABLE llm_profiles DROP CONSTRAINT IF EXISTS llm_profiles_format_check;
ALTER TABLE llm_profiles ADD  CONSTRAINT llm_profiles_format_check
    CHECK (format IN ('openai','anthropic','openai-responses'));

-- 输出上限及其字段名；补旧库。默认 0 / '' = 不发送上限、沿用 max_tokens 字段名，
-- 旧配置行为完全不变。
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS max_tokens       INTEGER NOT NULL DEFAULT 0;
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS max_tokens_field TEXT    NOT NULL DEFAULT '';
-- 同 format：先删再建，保证每次启动幂等。
ALTER TABLE llm_profiles DROP CONSTRAINT IF EXISTS llm_profiles_max_tokens_field_check;
ALTER TABLE llm_profiles ADD  CONSTRAINT llm_profiles_max_tokens_field_check
    CHECK (max_tokens_field IN ('','max_completion_tokens'));
ALTER TABLE llm_profiles DROP CONSTRAINT IF EXISTS llm_profiles_max_tokens_check;
ALTER TABLE llm_profiles ADD  CONSTRAINT llm_profiles_max_tokens_check
    CHECK (max_tokens >= 0);
-- 自定义会话头名；补旧库。默认 '' = 不发送，旧配置行为不变。
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS session_header_key TEXT NOT NULL DEFAULT '';

-- 单配置的重试覆盖（见 docs/LLM重试设计.md）。三组各自一对「次数 + 固定间隔」，
-- 语义统一：次数 0=沿用全局默认、-1=关闭该层重试、>0=用该值；间隔 0=沿用该层的
-- 默认指数退避、>0=改用这个固定毫秒数。全部默认 0，所以旧库/旧配置行为不变。
--   connect = 建连重试（SDK doStream：连接重置/超时/429/5xx，流开始前）
--   empty   = 空响应重试（SDK：完成但没有任何 content block，仅 openai 格式）
--   stream  = 同 provider 安全窗口重试（本项目 task_llm：未交付输出前的断流重放）
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_connect_attempts    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_connect_interval_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_empty_attempts      INTEGER NOT NULL DEFAULT 0;
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_empty_interval_ms   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_stream_attempts     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE llm_profiles ADD COLUMN IF NOT EXISTS retry_stream_interval_ms  INTEGER NOT NULL DEFAULT 0;
-- 同 format：先删再建，保证每次启动幂等。次数下限 -1(关闭)，间隔不能为负。
ALTER TABLE llm_profiles DROP CONSTRAINT IF EXISTS llm_profiles_retry_check;
ALTER TABLE llm_profiles ADD  CONSTRAINT llm_profiles_retry_check CHECK (
    retry_connect_attempts >= -1 AND retry_empty_attempts >= -1 AND retry_stream_attempts >= -1
    AND retry_connect_interval_ms >= 0 AND retry_empty_interval_ms >= 0 AND retry_stream_interval_ms >= 0);

-- 思考开关字段 thinking_type，从旧的单一 reasoning_effort 语义一次性拆分而来。
-- schema.sql 每次启动都执行，故迁移必须只跑一次：仅当该列尚不存在时才回填，
-- 否则每次启动都会把用户后来手动设的组合覆盖回去。旧 reasoning_effort 语义：
--   'off'                    → 显式关闭  → thinking_type='disabled'，强度清空
--   'low/medium/high/max'    → 开启+强度 → thinking_type='enabled'，强度保留
--   ''                       → 不发送    → 两者皆空(默认)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'llm_profiles' AND column_name = 'thinking_type'
    ) THEN
        ALTER TABLE llm_profiles ADD COLUMN thinking_type TEXT NOT NULL DEFAULT '';
        UPDATE llm_profiles SET thinking_type = 'enabled'
            WHERE reasoning_effort IN ('low','medium','high','max');
        UPDATE llm_profiles SET thinking_type = 'disabled', reasoning_effort = ''
            WHERE reasoning_effort = 'off';
    END IF;
END $$;

-- LLM 轮询熔断状态：某个配置连续失败(余额不足/key 失效/限流)后进入冷却，冷却期内
-- 轮询直接跳过它。内存态为准，这里落库只为重启后不丢冷却窗口——加载时只取尚未
-- 到期的行(open_until > now)，已到期的自然回到"正常"，等下一次调用半开试探。
CREATE TABLE IF NOT EXISTS llm_profile_health (
    profile_id  BIGINT PRIMARY KEY REFERENCES llm_profiles(id) ON DELETE CASCADE,
    fails       INTEGER NOT NULL DEFAULT 0,  -- 当前连续失败次数(成功即清零)
    trips       INTEGER NOT NULL DEFAULT 0,  -- 累计熔断次数,用于冷却时间指数退避
    open_until  TIMESTAMPTZ,                 -- 冷却截止;NULL/过期 = 未熔断
    last_error  TEXT NOT NULL DEFAULT '',
    last_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- =====================================================================
-- D. 任务层
-- =====================================================================
-- Global task categories are intentionally independent from task templates.
-- Deleting a category only moves its tasks back to the uncategorized bucket.
CREATE TABLE IF NOT EXISTS task_categories (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    nkey       TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_task_categories_name ON task_categories(name, id);
DROP TRIGGER IF EXISTS trg_task_categories_upd ON task_categories;
CREATE TRIGGER trg_task_categories_upd BEFORE UPDATE ON task_categories
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS tasks (
    id             BIGSERIAL PRIMARY KEY,
    name           TEXT NOT NULL DEFAULT '',
    category_id    BIGINT REFERENCES task_categories(id) ON DELETE SET NULL,
    description    TEXT NOT NULL,
    goal           TEXT NOT NULL,
    exploration_id BIGINT NOT NULL UNIQUE
                     REFERENCES explorations(id) ON DELETE RESTRICT,
    status         TEXT NOT NULL DEFAULT 'created'
                     CHECK (status IN ('created','running','paused','done','failed','timeout')),
    paused         BOOLEAN NOT NULL DEFAULT false,
    queued         BOOLEAN NOT NULL DEFAULT false,
    queued_at      TIMESTAMPTZ,
    queue_mode     TEXT NOT NULL DEFAULT '',
    llm_profile_id BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL,
    active_llm_profile_id BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL,
    llm_chain_revision BIGINT NOT NULL DEFAULT 0,
    company_id     BIGINT REFERENCES companies(id) ON DELETE SET NULL,
    parent_ref     TEXT,
    timeout_seconds INTEGER NOT NULL DEFAULT 0,
    plan_heartbeat_seconds INTEGER NOT NULL DEFAULT 300,
    coverage_enabled BOOLEAN NOT NULL DEFAULT true,
    pinned_at      TIMESTAMPTZ,
    first_run_at   TIMESTAMPTZ,
    deadline_at    TIMESTAMPTZ,
    archived_at    TIMESTAMPTZ,
    deleted_at     TIMESTAMPTZ,
    completed_at   TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_tasks_alive  ON tasks(created_at DESC) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)          WHERE deleted_at IS NULL;
DROP TRIGGER IF EXISTS trg_tasks_upd ON tasks;
CREATE TRIGGER trg_tasks_upd BEFORE UPDATE ON tasks
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
-- planner 心跳触发间隔(秒);补旧库。默认 300s(5min)。见 docs/planner-trigger-impl-plan.md
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS plan_heartbeat_seconds INTEGER NOT NULL DEFAULT 300;
-- 并发上限挂起态;补旧库。true=因并发上限排队、等待空位自动启动。
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS queued BOOLEAN NOT NULL DEFAULT false;
-- 资产覆盖度功能开关;补旧库。true(默认)=计算/展示测试覆盖度、自动累积测试范围、
-- 给 agent 开放 add_task_scope/list_untested_assets;false=全部关闭(见 task_scope.go)。
-- 存量任务默认 true 保持原行为;company 关联(task_scope kind=company)不受此开关影响。
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS coverage_enabled BOOLEAN NOT NULL DEFAULT true;
-- queued_at makes admission FIFO reflect the actual enqueue order rather than the
-- task creation order. queue_mode distinguishes first bootstrap from resuming an
-- exploration that already owns goals/history.
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS queued_at TIMESTAMPTZ;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS queue_mode TEXT NOT NULL DEFAULT '';
-- 可选的任务名称;补旧库。空串=未命名,前端展示时回退到描述。
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '';
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS remark TEXT NOT NULL DEFAULT '';
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS category_id BIGINT REFERENCES task_categories(id) ON DELETE SET NULL;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS pinned_at TIMESTAMPTZ;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS active_llm_profile_id BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS llm_chain_revision BIGINT NOT NULL DEFAULT 0;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_tasks_category ON tasks(category_id, created_at DESC)
    WHERE deleted_at IS NULL AND category_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tasks_pinned ON tasks(pinned_at DESC)
    WHERE deleted_at IS NULL AND pinned_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tasks_archived ON tasks(archived_at DESC)
    WHERE archived_at IS NOT NULL;

-- Cold task archives retain only compact metadata in PostgreSQL. The complete
-- task payload lives in a versioned .tar.zst package under data/archives/tasks.
-- task_id stays unique so an operation can be retried safely after a restart.
CREATE TABLE IF NOT EXISTS task_archives (
    id                         BIGSERIAL PRIMARY KEY,
    task_id                    BIGINT NOT NULL UNIQUE REFERENCES tasks(id) ON DELETE CASCADE,
    state                      TEXT NOT NULL DEFAULT 'archive_queued' CHECK (state IN (
                                   'archive_queued','archiving','archive_failed','ready',
                                   'restore_queued','restoring','restore_failed',
                                   'delete_queued','deleting','delete_failed'
                               )),
    phase                      TEXT NOT NULL DEFAULT 'queued',
    progress                   INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    error                      TEXT NOT NULL DEFAULT '',
    warnings                   JSONB NOT NULL DEFAULT '[]',
    format_version             INTEGER NOT NULL DEFAULT 2,
    archive_path               TEXT NOT NULL DEFAULT '',
    sha256                     TEXT NOT NULL DEFAULT '',
    original_size              BIGINT NOT NULL DEFAULT 0,
    compressed_size            BIGINT NOT NULL DEFAULT 0,
    task_name                  TEXT NOT NULL DEFAULT '',
    task_description           TEXT NOT NULL DEFAULT '',
    task_goal                  TEXT NOT NULL DEFAULT '',
    original_status            TEXT NOT NULL DEFAULT '',
    category_id_snapshot       BIGINT,
    category_name_snapshot     TEXT NOT NULL DEFAULT '',
    source_task_ids            BIGINT[] NOT NULL DEFAULT '{}',
    remaining_timeout_seconds  BIGINT NOT NULL DEFAULT 0,
    data_counts                JSONB NOT NULL DEFAULT '{}',
    aggregate_stats            JSONB NOT NULL DEFAULT '{}',
    archived_at                TIMESTAMPTZ,
    requested_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE task_archives ALTER COLUMN format_version SET DEFAULT 2;
CREATE INDEX IF NOT EXISTS idx_task_archives_state ON task_archives(state, requested_at, id);
CREATE INDEX IF NOT EXISTS idx_task_archives_archived ON task_archives(archived_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_task_archives_sources ON task_archives USING GIN(source_task_ids);
DROP TRIGGER IF EXISTS trg_task_archives_upd ON task_archives;
CREATE TRIGGER trg_task_archives_upd BEFORE UPDATE ON task_archives
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Reusable task description/goal presets. nkey is the normalized, case-insensitive
-- identity used to reject visually equivalent duplicate names.
CREATE TABLE IF NOT EXISTS task_templates (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    nkey        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    goal        TEXT NOT NULL,
    -- 预设的任务分类；分类删除时置空（与 tasks.category_id 一致，不阻断）。
    category_id     BIGINT REFERENCES task_categories(id) ON DELETE SET NULL,
    -- 预设的任务级拦截/允许规则快照(AssetInterceptRuleInput 数组)；应用模板时灌进新任务。
    intercept_rules JSONB NOT NULL DEFAULT '[]',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- 补旧库(已发版,加列带 IF NOT EXISTS)。
ALTER TABLE task_templates ADD COLUMN IF NOT EXISTS category_id BIGINT REFERENCES task_categories(id) ON DELETE SET NULL;
ALTER TABLE task_templates ADD COLUMN IF NOT EXISTS intercept_rules JSONB NOT NULL DEFAULT '[]';
CREATE INDEX IF NOT EXISTS idx_task_templates_updated ON task_templates(updated_at DESC, id DESC);
DROP TRIGGER IF EXISTS trg_task_templates_upd ON task_templates;
CREATE TRIGGER trg_task_templates_upd BEFORE UPDATE ON task_templates
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Direct, read-only task context inheritance. Relations are intentionally not
-- recursive: a task sees only the source tasks explicitly chosen at creation.
CREATE TABLE IF NOT EXISTS task_relations (
    task_id        BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    source_task_id BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (task_id, source_task_id),
    CONSTRAINT ck_task_relation_not_self CHECK (task_id <> source_task_id)
);
CREATE INDEX IF NOT EXISTS idx_task_relations_source ON task_relations(source_task_id);

-- Task/asset provenance supplements the legacy assets.task_ids association. The
-- array remains the compatibility source for existing query and cleanup paths;
-- this relation records how each association was obtained for operator review.
CREATE TABLE IF NOT EXISTS task_asset_links (
    task_id        BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    asset_id       BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    source         TEXT NOT NULL DEFAULT 'system',
    source_summary TEXT NOT NULL DEFAULT '',
    source_node_id BIGINT REFERENCES exploration_nodes(id) ON DELETE SET NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (task_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_task_asset_links_asset ON task_asset_links(asset_id, task_id);
CREATE INDEX IF NOT EXISTS idx_task_asset_links_node ON task_asset_links(source_node_id)
    WHERE source_node_id IS NOT NULL;
DROP TRIGGER IF EXISTS trg_task_asset_links_upd ON task_asset_links;
CREATE TRIGGER trg_task_asset_links_upd BEFORE UPDATE ON task_asset_links
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Keep provenance rows synchronized when existing asset upsert paths append or
-- remove task ids. Detailed callers overwrite the generic source after upsert.
CREATE OR REPLACE FUNCTION sync_task_asset_links() RETURNS trigger AS $$
BEGIN
    INSERT INTO task_asset_links(task_id, asset_id, source, source_summary)
    SELECT task.id, NEW.id, 'system', '任务执行期间自动关联'
    FROM unnest(NEW.task_ids) AS requested(task_id)
    JOIN tasks task ON task.id=requested.task_id AND task.deleted_at IS NULL
    ON CONFLICT (task_id, asset_id) DO NOTHING;

    DELETE FROM task_asset_links link
    WHERE link.asset_id=NEW.id
      AND NOT (link.task_id=ANY(NEW.task_ids));
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_assets_task_links ON assets;
CREATE TRIGGER trg_assets_task_links AFTER INSERT OR UPDATE OF task_ids ON assets
    FOR EACH ROW EXECUTE FUNCTION sync_task_asset_links();

-- Existing installations receive an auditable legacy source without rewriting
-- task_ids. Ignore stale array ids that no longer resolve to a live task.
INSERT INTO task_asset_links(task_id, asset_id, source, source_summary)
SELECT task.id, asset.id, 'legacy', '由历史任务资产关联迁移'
FROM assets asset
CROSS JOIN LATERAL unnest(asset.task_ids) AS requested(task_id)
JOIN tasks task ON task.id=requested.task_id AND task.deleted_at IS NULL
ON CONFLICT (task_id, asset_id) DO NOTHING;

-- Ordered task-level LLM failover chain. A failed entry (quota exhausted, or a
-- configuration-class rejection such as 401/403/404) is skipped until the user
-- saves/resets the chain, which clears all failure state.
CREATE TABLE IF NOT EXISTS task_llm_profiles (
    task_id          BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    profile_id       BIGINT NOT NULL REFERENCES llm_profiles(id) ON DELETE CASCADE,
    position         INTEGER NOT NULL CHECK (position >= 0),
    status           TEXT NOT NULL DEFAULT 'ready'
                       CHECK (status IN ('ready','quota_exhausted','unavailable')),
    last_error       TEXT,
    exhausted_at     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (task_id, profile_id),
    UNIQUE (task_id, position)
);
-- Existing installations predate the 'unavailable' status: recreate the check
-- constraint idempotently on every startup.
ALTER TABLE task_llm_profiles DROP CONSTRAINT IF EXISTS task_llm_profiles_status_check;
ALTER TABLE task_llm_profiles ADD CONSTRAINT task_llm_profiles_status_check
    CHECK (status IN ('ready','quota_exhausted','unavailable'));
CREATE INDEX IF NOT EXISTS idx_task_llm_profiles_order ON task_llm_profiles(task_id, position);
CREATE INDEX IF NOT EXISTS idx_task_llm_profiles_profile ON task_llm_profiles(profile_id, task_id);
CREATE INDEX IF NOT EXISTS idx_tasks_llm_profile ON tasks(llm_profile_id) WHERE llm_profile_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tasks_active_llm_profile ON tasks(active_llm_profile_id) WHERE active_llm_profile_id IS NOT NULL;
DROP TRIGGER IF EXISTS trg_task_llm_profiles_upd ON task_llm_profiles;
CREATE TRIGGER trg_task_llm_profiles_upd BEFORE UPDATE ON task_llm_profiles
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- One-time-compatible backfill: old pinned tasks become one-entry chains. A user
-- can still clear the chain later because the update path also clears the legacy
-- llm_profile_id column, preventing this block from re-adding it on restart.
INSERT INTO task_llm_profiles(task_id, profile_id, position)
SELECT t.id, t.llm_profile_id, 0
FROM tasks t
WHERE t.llm_profile_id IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM task_llm_profiles x WHERE x.task_id=t.id)
ON CONFLICT DO NOTHING;
UPDATE tasks t
SET active_llm_profile_id = t.llm_profile_id
WHERE t.active_llm_profile_id IS NULL
  AND t.llm_profile_id IS NOT NULL
  AND EXISTS (SELECT 1 FROM task_llm_profiles x WHERE x.task_id=t.id AND x.profile_id=t.llm_profile_id);

-- 任务测试范围（资产覆盖度的分母 + 授权边界）。
--   自动填(source='auto')：insertAssets 顶层按 worker 显式插入的资产类型加保守范围
--     （root_domain→root_domain，subdomain/service/endpoint→subdomain(host)，ip→ip）；
--     side-effect 派生的资产不入范围（钩子在 handler 顶层，派生在 db 层内部）。
--   agent 填(source='agent')：add_task_scope 加 company/root_domain/subdomain/ip。
-- 覆盖度 = 匹配 active 行的 assets（分母）中，被 fact 节点锚定过的占比（分子）。
CREATE TABLE IF NOT EXISTS task_scope (
    id          BIGSERIAL PRIMARY KEY,
    task_id     BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('company','root_domain','subdomain','ip','cidr','icp','keyword')),
    company_id  BIGINT REFERENCES companies(id) ON DELETE CASCADE,  -- kind='company'
    domain      TEXT,          -- root_domain / subdomain
    net         CIDR,          -- ip / cidr
    value       TEXT,          -- icp / keyword
    source      TEXT NOT NULL DEFAULT 'auto' CHECK (source IN ('auto','agent','manual')),
    reason      TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- 旧库升级：扩展任务范围，使其与企业范围的单文本框识别能力一致。
ALTER TABLE task_scope ADD COLUMN IF NOT EXISTS value TEXT;
ALTER TABLE task_scope DROP CONSTRAINT IF EXISTS task_scope_kind_check;
ALTER TABLE task_scope ADD CONSTRAINT task_scope_kind_check
    CHECK (kind IN ('company','root_domain','subdomain','ip','cidr','icp','keyword'));
-- 去重：同一 task 的同一条范围只存一次（自动填批量插入靠它幂等）。
DROP INDEX IF EXISTS uq_task_scope;
CREATE UNIQUE INDEX IF NOT EXISTS uq_task_scope_v2 ON task_scope(
    task_id, kind, COALESCE(domain,''), COALESCE(net::text,''), COALESCE(company_id,0), COALESCE(value,''));
CREATE INDEX IF NOT EXISTS idx_ts_domain  ON task_scope(domain) WHERE kind IN ('root_domain','subdomain');
CREATE INDEX IF NOT EXISTS idx_ts_net     ON task_scope USING GIST(net inet_ops) WHERE kind IN ('ip','cidr');
CREATE INDEX IF NOT EXISTS idx_ts_company ON task_scope(company_id) WHERE kind = 'company';

-- =====================================================================
-- E. Agents / 提示词模板 / 变量目录
-- =====================================================================
CREATE TABLE IF NOT EXISTS agents (
    id                BIGSERIAL PRIMARY KEY,
    key               TEXT NOT NULL UNIQUE CHECK (key ~ '^[a-z][a-z0-9_]*$'),
    name              TEXT NOT NULL,
    description       TEXT,
    role              TEXT NOT NULL,
    builtin           BOOLEAN NOT NULL DEFAULT true,
    enabled           BOOLEAN NOT NULL DEFAULT true,
    llm_profile_id    BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL,
    current_prompt_id BIGINT,
    max_turns         INTEGER NOT NULL DEFAULT 0,
    run_seconds       INTEGER NOT NULL DEFAULT 1200,
    web_search        BOOLEAN NOT NULL DEFAULT false,
    interactive_shell BOOLEAN NOT NULL DEFAULT false,
    wrapup_prompt     TEXT NOT NULL DEFAULT '',
    wrapup_max_turns  INTEGER NOT NULL DEFAULT 0,
    task_timeout_wrapup_prompt    TEXT NOT NULL DEFAULT '',
    task_timeout_wrapup_max_turns INTEGER NOT NULL DEFAULT 0,
    trigger_run_mode     TEXT    NOT NULL DEFAULT 'serial'  CHECK (trigger_run_mode IN ('serial','parallel')),
    trigger_merge_mode   TEXT    NOT NULL DEFAULT 'all' CHECK (trigger_merge_mode IN ('by_task','all','none')),
    trigger_max_parallel INTEGER NOT NULL DEFAULT 5,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT agents_role_ck CHECK (role IN ('goals','main','planner','worker','assistant'))
);
-- 加列迁移(已发版,旧库升级补列;新库 CREATE 已含。迁移不带 CHECK:旧库存量安全 + 后端写入白名单兜底)。
ALTER TABLE agents ADD COLUMN IF NOT EXISTS trigger_run_mode     TEXT    NOT NULL DEFAULT 'serial';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS trigger_merge_mode   TEXT    NOT NULL DEFAULT 'all';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS trigger_max_parallel INTEGER NOT NULL DEFAULT 5;
-- per-agent LLM 绑定(agent 级默认模型):列自初版即在上方 CREATE 中,此 ALTER 仅为极旧库兜底(幂等)。
ALTER TABLE agents ADD COLUMN IF NOT EXISTS llm_profile_id BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL;
-- run_seconds 单次 run 墙钟默认 600→1200:只改列默认(影响将来新插入的行),不动旧库存量行。
ALTER TABLE agents ALTER COLUMN run_seconds SET DEFAULT 1200;
CREATE INDEX IF NOT EXISTS idx_agents_llm_profile ON agents(llm_profile_id) WHERE llm_profile_id IS NOT NULL;
DROP TRIGGER IF EXISTS trg_agents_upd ON agents;
CREATE TRIGGER trg_agents_upd BEFORE UPDATE ON agents
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS agent_prompts (
    id            BIGSERIAL PRIMARY KEY,
    agent_id      BIGINT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    version       INT NOT NULL,
    template_text TEXT NOT NULL,
    note          TEXT,
    updated_by    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (agent_id, version)
);
-- 循环外键：agents.current_prompt_id → agent_prompts.id（需在两表创建后加）
DO $$ BEGIN
    ALTER TABLE agents ADD CONSTRAINT fk_agents_curprompt
        FOREIGN KEY (current_prompt_id) REFERENCES agent_prompts(id) ON DELETE SET NULL;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS agent_prompt_vars (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    BIGINT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    var_name    TEXT NOT NULL,
    description TEXT,
    example     TEXT,
    source      TEXT NOT NULL CHECK (source IN ('exploration','runtime','distilled')),
    UNIQUE (agent_id, var_name)
);

-- =====================================================================
-- F. MCP 服务
-- =====================================================================
CREATE TABLE IF NOT EXISTS mcp_servers (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    transport   TEXT NOT NULL CHECK (transport IN ('stdio','http','sse')),
    command     TEXT,
    args        JSONB NOT NULL DEFAULT '[]',
    env         JSONB NOT NULL DEFAULT '{}',
    url         TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    insecure    BOOLEAN NOT NULL DEFAULT false,  -- http: 跳过 TLS 证书校验(自签证书场景, issue #108)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Allow legacy MCP SSE servers on databases created before SSE support.
ALTER TABLE mcp_servers DROP CONSTRAINT IF EXISTS mcp_servers_transport_check;
ALTER TABLE mcp_servers ADD CONSTRAINT mcp_servers_transport_check
    CHECK (transport IN ('stdio','http','sse'));
-- 旧库补列(schema.sql 每次启动都会 Exec)。
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS insecure BOOLEAN NOT NULL DEFAULT false;
DROP TRIGGER IF EXISTS trg_mcp_upd ON mcp_servers;
CREATE TRIGGER trg_mcp_upd BEFORE UPDATE ON mcp_servers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS mcp_tools_cache (
    id            BIGSERIAL PRIMARY KEY,
    server_id     BIGINT NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
    tool_name     TEXT NOT NULL,
    description   TEXT,
    schema        JSONB,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (server_id, tool_name)
);

-- =====================================================================
-- G. 可见性：agent × mcp / skill
-- =====================================================================
CREATE TABLE IF NOT EXISTS agent_visibility (
    agent_id      BIGINT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    resource_kind TEXT   NOT NULL CHECK (resource_kind IN ('mcp')),
    resource_id   BIGINT NOT NULL,
    mcp_tool_name TEXT   NOT NULL DEFAULT '',
    enabled       BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, resource_kind, resource_id, mcp_tool_name)
);
CREATE INDEX IF NOT EXISTS idx_vis_resource ON agent_visibility(resource_kind, resource_id);

CREATE TABLE IF NOT EXISTS agent_skill_visibility (
    agent_id   BIGINT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    skill_name TEXT   NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, skill_name)
);
CREATE INDEX IF NOT EXISTS idx_askv_skill ON agent_skill_visibility(skill_name);

-- Skill 调用账本（见 db/skill_usage.go）。一次 Skill() 调用一行，只记维度不记正文。
-- 刻意不设外键：任务/会话删除后统计仍要保留（与 llm_usage 同理），skill 本身也只是
-- 文件系统上的目录名，没有对应的表。
CREATE TABLE IF NOT EXISTS skill_usage (
    id             BIGSERIAL PRIMARY KEY,
    ts             TIMESTAMPTZ NOT NULL DEFAULT now(),
    skill          TEXT NOT NULL,
    agent_key      TEXT,
    task_id        BIGINT,
    exploration_id BIGINT,
    intent_id      BIGINT,
    session_id     TEXT,
    args_len       INTEGER NOT NULL DEFAULT 0,
    -- false = 模型点名了一个不存在的 skill(未命中)。这类行同样保留：它反映"想用但没有"
    -- 的缺口，是补 skill 的依据。
    found          BOOLEAN NOT NULL DEFAULT true
);
CREATE INDEX IF NOT EXISTS idx_skill_usage_skill ON skill_usage(skill, ts DESC);
CREATE INDEX IF NOT EXISTS idx_skill_usage_task  ON skill_usage(task_id);

-- 工具调用账本（见 db/tool_usage.go）。一次实际 CoreTool.Call 一行，只记归属维度，
-- 不保存工具参数或返回内容。刻意不设外键，任务、会话或自定义工具删除后仍保留统计。
CREATE TABLE IF NOT EXISTS tool_usage (
    id             BIGSERIAL PRIMARY KEY,
    ts             TIMESTAMPTZ NOT NULL DEFAULT now(),
    tool_key       TEXT NOT NULL,
    agent_key      TEXT,
    task_id        BIGINT,
    exploration_id BIGINT,
    intent_id      BIGINT,
    session_id     TEXT
);
CREATE INDEX IF NOT EXISTS idx_tool_usage_tool ON tool_usage(tool_key, ts DESC);
CREATE INDEX IF NOT EXISTS idx_tool_usage_task ON tool_usage(task_id);

-- =====================================================================
-- H. 内置工具目录
-- =====================================================================
CREATE TABLE IF NOT EXISTS tools (
    key         TEXT PRIMARY KEY,
    system      BOOLEAN NOT NULL DEFAULT true,
    description TEXT    NOT NULL DEFAULT '',
    schema      JSONB   NOT NULL DEFAULT '{}',
    agents      JSONB   NOT NULL DEFAULT '[]',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    kind        TEXT    NOT NULL DEFAULT 'builtin',
    exec        JSONB   NOT NULL DEFAULT '{}',
    deferred    BOOLEAN NOT NULL DEFAULT false,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
DROP TRIGGER IF EXISTS trg_tools_upd ON tools;
CREATE TRIGGER trg_tools_upd BEFORE UPDATE ON tools
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- =====================================================================
-- I. 会话（对话页）
-- =====================================================================
CREATE TABLE IF NOT EXISTS conversations (
    id             BIGSERIAL PRIMARY KEY,
    agent_key      TEXT NOT NULL,
    title          TEXT NOT NULL DEFAULT '',
    llm_profile_id BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL,
    pinned_at      TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS pinned_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_conversations_llm_profile ON conversations(llm_profile_id) WHERE llm_profile_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_conversations_pinned ON conversations(pinned_at DESC) WHERE pinned_at IS NOT NULL;
DROP TRIGGER IF EXISTS trg_conversations_upd ON conversations;
CREATE TRIGGER trg_conversations_upd BEFORE UPDATE ON conversations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS conversation_activities (
    id                 BIGSERIAL PRIMARY KEY,
    conversation_id    BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    worker             TEXT,
    kind               TEXT,
    tool               TEXT,
    tool_use_id        TEXT,
    is_error           BOOLEAN NOT NULL DEFAULT false,
    summary            TEXT,
    detail             TEXT,
    input_tokens       INTEGER,
    output_tokens      INTEGER,
    cache_read_tokens  INTEGER,
    cache_write_tokens INTEGER,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_conv_act ON conversation_activities(conversation_id, id);
CREATE INDEX IF NOT EXISTS idx_conv_act_tool_call ON conversation_activities(conversation_id, tool_use_id, id)
  WHERE kind IN ('tool_use', 'tool_result');

-- =====================================================================
-- J. Agent 触发器
-- =====================================================================
CREATE TABLE IF NOT EXISTS agent_triggers (
    id                          BIGSERIAL PRIMARY KEY,
    agent_key                   TEXT NOT NULL,
    enabled                     BOOLEAN NOT NULL DEFAULT true,
    interval_sec                INTEGER NOT NULL DEFAULT 0,
    on_finding                  BOOLEAN NOT NULL DEFAULT false,
    on_goal_met                 BOOLEAN NOT NULL DEFAULT false,
    on_task_timeout             BOOLEAN NOT NULL DEFAULT false,
    on_tool_call                BOOLEAN NOT NULL DEFAULT false,
    on_task_create              BOOLEAN NOT NULL DEFAULT false,
    interval_message            TEXT NOT NULL DEFAULT '',
    finding_message             TEXT NOT NULL DEFAULT '',
    goal_message                TEXT NOT NULL DEFAULT '',
    task_timeout_message        TEXT NOT NULL DEFAULT '',
    tool_call_message           TEXT NOT NULL DEFAULT '',
    task_create_message         TEXT NOT NULL DEFAULT '',
    tool_names                  TEXT NOT NULL DEFAULT '',
    last_fire                   TIMESTAMPTZ,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_agent_triggers_agent ON agent_triggers(agent_key);
-- 加列迁移(已发版,旧库升级补列;新库 CREATE 已含这些列,ALTER 为 no-op)。幂等,每次启动可重复执行。
ALTER TABLE agent_triggers ADD COLUMN IF NOT EXISTS on_tool_call        BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE agent_triggers ADD COLUMN IF NOT EXISTS tool_call_message   TEXT    NOT NULL DEFAULT '';
ALTER TABLE agent_triggers ADD COLUMN IF NOT EXISTS tool_names          TEXT    NOT NULL DEFAULT '';
ALTER TABLE agent_triggers ADD COLUMN IF NOT EXISTS on_task_create      BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE agent_triggers ADD COLUMN IF NOT EXISTS task_create_message TEXT    NOT NULL DEFAULT '';
DROP TRIGGER IF EXISTS trg_agent_triggers_upd ON agent_triggers;
CREATE TRIGGER trg_agent_triggers_upd BEFORE UPDATE ON agent_triggers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS scheduler_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

-- =====================================================================
-- J1. Calendar based task schedules
-- =====================================================================
CREATE TABLE IF NOT EXISTS task_schedules (
    id                 BIGSERIAL PRIMARY KEY,
    name               TEXT NOT NULL,
    enabled            BOOLEAN NOT NULL DEFAULT true,
    timezone_mode      TEXT NOT NULL DEFAULT 'beijing'
                       CHECK (timezone_mode IN ('beijing','system')),
    schedule_type      TEXT NOT NULL DEFAULT 'weekly'
                       CHECK (schedule_type IN ('once','weekly')),
    run_date           DATE,
    end_date           DATE,
    weekdays           TEXT NOT NULL DEFAULT '',
    start_time         TIME NOT NULL,
    end_time           TIME,
    start_immediately  BOOLEAN NOT NULL DEFAULT false,
    status             TEXT NOT NULL DEFAULT 'waiting'
                       CHECK (status IN ('waiting','running','outside','completed','error','paused')),
    last_window_key    TEXT NOT NULL DEFAULT '',
    last_transition_at TIMESTAMPTZ,
    last_error         TEXT NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((schedule_type = 'once' AND run_date IS NOT NULL) OR
           (schedule_type = 'weekly' AND run_date IS NULL)),
    CHECK ((schedule_type = 'once') OR weekdays <> '')
);
CREATE INDEX IF NOT EXISTS idx_task_schedules_enabled ON task_schedules(enabled, id);
ALTER TABLE task_schedules ADD COLUMN IF NOT EXISTS end_date DATE;
ALTER TABLE task_schedules ADD COLUMN IF NOT EXISTS remark TEXT NOT NULL DEFAULT '';
DROP TRIGGER IF EXISTS trg_task_schedules_upd ON task_schedules;
CREATE TRIGGER trg_task_schedules_upd BEFORE UPDATE ON task_schedules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS task_schedule_tasks (
    schedule_id BIGINT NOT NULL REFERENCES task_schedules(id) ON DELETE CASCADE,
    task_id     BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    paused_by_schedule BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (schedule_id, task_id)
);
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS schedule_paused BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS schedule_manual_until TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_task_schedule_tasks_task ON task_schedule_tasks(task_id);
ALTER TABLE task_schedule_tasks ADD COLUMN IF NOT EXISTS paused_by_schedule BOOLEAN NOT NULL DEFAULT false;

-- =====================================================================
-- K. 拦截规则
-- =====================================================================
CREATE TABLE IF NOT EXISTS intercept_rules (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    priority        INTEGER NOT NULL DEFAULT 0,
    match_target    TEXT NOT NULL CHECK (match_target IN ('tool_name', 'tool_input')),
    match_type      TEXT NOT NULL CHECK (match_type IN ('string', 'regex')),
    pattern         TEXT NOT NULL,
    action          TEXT NOT NULL CHECK (action IN ('allow', 'deny', 'ask')),
    message         TEXT NOT NULL DEFAULT '',
    timeout_enabled BOOLEAN NOT NULL DEFAULT true,
    timeout_seconds INTEGER NOT NULL DEFAULT 60,
    timeout_action  TEXT    NOT NULL DEFAULT 'deny',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
DROP TRIGGER IF EXISTS trg_intercept_rules_upd ON intercept_rules;
CREATE TRIGGER trg_intercept_rules_upd BEFORE UPDATE ON intercept_rules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS intercept_pending (
    id              BIGSERIAL PRIMARY KEY,
    rule_id         BIGINT REFERENCES intercept_rules(id) ON DELETE SET NULL,
    conversation_id BIGINT REFERENCES conversations(id) ON DELETE CASCADE,
    task_id         TEXT,
    agent_name      TEXT NOT NULL DEFAULT '',
    tool_name       TEXT NOT NULL,
    tool_input      JSONB NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'allowed', 'denied', 'timeout')),
    -- 判定理由:规则命中时为规则 message;LLM 兜底判定时为模型给的简短理由(前缀 [模型])。
    reason          TEXT NOT NULL DEFAULT '',
    decided_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_intercept_pending_status ON intercept_pending(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_intercept_pending_task   ON intercept_pending(task_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_intercept_pending_created ON intercept_pending(created_at DESC);
-- 补旧库:reason 列(已发版,加列要带 IF NOT EXISTS)。
ALTER TABLE intercept_pending ADD COLUMN IF NOT EXISTS reason TEXT NOT NULL DEFAULT '';
-- Detail payloads are lazy-loaded; NULL preserves the meaning of legacy history.
ALTER TABLE intercept_pending ADD COLUMN IF NOT EXISTS audit JSONB;
ALTER TABLE intercept_pending ADD COLUMN IF NOT EXISTS decision_source TEXT NOT NULL DEFAULT '';
UPDATE intercept_pending SET decision_source=CASE WHEN rule_id IS NOT NULL THEN 'rule'
 WHEN reason LIKE '[模型]%' THEN 'model' ELSE 'unknown' END WHERE decision_source='';
-- 审批请求的初判来源可能是规则/模型，但最终由用户允许或拒绝；保留最终人工判定来源。
UPDATE intercept_pending SET decision_source='manual'
 WHERE decision_source <> 'manual'
   AND (audit->>'decision_reason' LIKE '人工允许%' OR audit->>'decision_reason' LIKE '人工拒绝%');

-- =====================================================================
-- L. 漏洞发现持久化
-- =====================================================================
CREATE TABLE IF NOT EXISTS findings (
    id          BIGSERIAL PRIMARY KEY,
    task_id     BIGINT REFERENCES tasks(id) ON DELETE SET NULL,
    node_id     BIGINT REFERENCES exploration_nodes(id) ON DELETE SET NULL,
    vulnclass   TEXT NOT NULL DEFAULT '',
    -- 漏洞名称(可读标题)；为空时前端回退展示 vulnclass。severity 取值：
    -- critical 严重 / high 高 / medium 中 / low 低（不加 CHECK，与 status 一致由 server 白名单校验）。
    name        TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT '',
    summary     TEXT NOT NULL DEFAULT '',
    evidence    TEXT NOT NULL DEFAULT '',
    worker      TEXT NOT NULL DEFAULT '',
    asset_ids   JSONB NOT NULL DEFAULT '[]',
    -- 处置状态：pending 待处理 / in_progress 处理中 / confirmed 已确认 / resolved 已处理 / fixed 已修复 /
    -- false_positive 误报 / ignored 忽略 / duplicate 重复 / risk_accepted 风险接受。
    -- 取值不加 CHECK：旧库靠下面的 ALTER 补列,CHECK 无法回填,统一由 server 侧白名单校验。
    status      TEXT NOT NULL DEFAULT 'pending',
    -- 漏洞详细报告(Markdown)；默认空,仅详情页读取/展示,不进列表接口以免 payload 膨胀。
    report      TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS name   TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS report TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cvss NUMERIC(3,1);
-- 结构化复现过程：agent 在 report_finding 落库时就地记录，而不是事后从证据文本重构。
-- 形状 {entry_point, prerequisites[], steps[{request,response,expected,proves,snapshot_id}], provenance}；
-- steps[].request/response 是当时真实收发的原文，steps[].snapshot_id 指向本漏洞已绑定的流量快照，
-- 报告据此把「第 N 步」和它自己的那条报文放在一起。
ALTER TABLE findings ADD COLUMN IF NOT EXISTS reproduction JSONB;

CREATE TABLE IF NOT EXISTS finding_review_events (
    id BIGSERIAL PRIMARY KEY,
    finding_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    action TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    from_val TEXT,
    to_val TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_finding_review_events_finding ON finding_review_events(finding_id);

CREATE TABLE IF NOT EXISTS finding_screenshots (
    id BIGSERIAL PRIMARY KEY,
    finding_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    caption TEXT NOT NULL DEFAULT '',
    data TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_finding_screenshots_finding ON finding_screenshots(finding_id);
-- 原始 HTTP 请求/响应报文(PoC 原文)；由 nuclei -irr 或深度利用记录写入。
-- 非 HTTP 漏洞或未采集时为空字符串，与「空报告」区分开。
ALTER TABLE findings ADD COLUMN IF NOT EXISTS http_request  TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS http_response TEXT NOT NULL DEFAULT '';
-- Canonical dedupe key (template + origin + path) for findings produced by
-- scans and deep exploitation. NULL means "do not dedupe" (manual findings).
ALTER TABLE findings ADD COLUMN IF NOT EXISTS dedupe_key TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedupe_key ON findings(dedupe_key);
CREATE INDEX IF NOT EXISTS idx_findings_task ON findings(task_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_time ON findings(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status, created_at DESC);
-- 「按资产」视图靠 asset_ids @> '[<id>]' 反查发现,没有这个 GIN 索引就是全表扫。
CREATE INDEX IF NOT EXISTS idx_findings_asset_ids ON findings USING GIN(asset_ids jsonb_path_ops);

-- 手动复测属于独立会话；结论与原漏洞处置状态分开保存。
CREATE TABLE IF NOT EXISTS finding_retests (
    id BIGSERIAL PRIMARY KEY,
    finding_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    conversation_id BIGINT UNIQUE REFERENCES conversations(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','completed','failed','stopped')),
    verdict TEXT NOT NULL DEFAULT '' CHECK (verdict IN ('','reproduced','fixed','inconclusive')),
    notes TEXT NOT NULL DEFAULT '',
    snapshot JSONB NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_finding_retests_history ON finding_retests(finding_id, id DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_retests_active ON finding_retests(finding_id)
    WHERE status IN ('pending','running');

-- 删除会话保留复测记录，同时解除尚未结束的复测占用。
CREATE OR REPLACE FUNCTION stop_deleted_conversation_retest() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE finding_retests SET status='stopped', error='复测会话已删除', finished_at=now()
    WHERE conversation_id=OLD.id AND status IN ('pending','running');
    RETURN OLD;
END;
$$;
DROP TRIGGER IF EXISTS trg_conversation_retest_delete ON conversations;
CREATE TRIGGER trg_conversation_retest_delete BEFORE DELETE ON conversations
    FOR EACH ROW EXECUTE FUNCTION stop_deleted_conversation_retest();

ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence_version BIGINT NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS report_evidence_version BIGINT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS traffic_evidence_snapshots (
    id TEXT PRIMARY KEY,
    source_traffic_id TEXT NOT NULL,
    captured_at BIGINT NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL,
    status INTEGER NOT NULL,
    content_type TEXT NOT NULL DEFAULT '',
    req_head TEXT NOT NULL,
    resp_head TEXT NOT NULL,
    req_hash TEXT NOT NULL,
    resp_hash TEXT NOT NULL,
    req_len BIGINT NOT NULL,
    resp_len BIGINT NOT NULL,
    unreferenced_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS finding_traffic_bindings (
    id BIGSERIAL PRIMARY KEY,
    finding_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    snapshot_id TEXT NOT NULL REFERENCES traffic_evidence_snapshots(id),
    role TEXT NOT NULL DEFAULT 'supporting',
    note TEXT NOT NULL DEFAULT '',
    position INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(finding_id, snapshot_id)
);
CREATE INDEX IF NOT EXISTS idx_finding_traffic_order ON finding_traffic_bindings(finding_id, position, id);
CREATE INDEX IF NOT EXISTS idx_finding_traffic_snapshot ON finding_traffic_bindings(snapshot_id);

-- =====================================================================
-- M. 后端日志持久化
-- =====================================================================
CREATE TABLE IF NOT EXISTS server_logs (
    id         BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    level      TEXT NOT NULL DEFAULT 'info',
    tag        TEXT NOT NULL DEFAULT '',
    text       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_server_logs_id ON server_logs(id DESC);

-- Independent /btw history and the latest provider-ready main checkpoint.
CREATE TABLE IF NOT EXISTS side_question_sessions (
    session_key TEXT PRIMARY KEY,
    conversation_id BIGINT REFERENCES conversations(id) ON DELETE CASCADE,
    task_id BIGINT REFERENCES tasks(id) ON DELETE CASCADE,
    exploration_id BIGINT REFERENCES explorations(id) ON DELETE CASCADE,
    intent_id BIGINT REFERENCES exploration_nodes(id) ON DELETE CASCADE,
    approval_id BIGINT REFERENCES intercept_pending(id) ON DELETE CASCADE,
    run_id BIGINT NOT NULL,
    version BIGINT NOT NULL,
    snapshot JSONB NOT NULL,
    generation BIGINT NOT NULL DEFAULT 0,
    CHECK (approval_id IS NOT NULL OR
        (conversation_id IS NOT NULL AND task_id IS NULL AND exploration_id IS NULL AND intent_id IS NULL)
        OR (conversation_id IS NULL AND task_id IS NOT NULL AND exploration_id IS NOT NULL))
);
ALTER TABLE side_question_sessions ADD COLUMN IF NOT EXISTS approval_id BIGINT REFERENCES intercept_pending(id) ON DELETE CASCADE;
ALTER TABLE side_question_sessions DROP CONSTRAINT IF EXISTS side_question_sessions_check;
ALTER TABLE side_question_sessions ADD CONSTRAINT side_question_sessions_check CHECK (approval_id IS NOT NULL OR
    (conversation_id IS NOT NULL AND task_id IS NULL AND exploration_id IS NULL AND intent_id IS NULL)
    OR (conversation_id IS NULL AND task_id IS NOT NULL AND exploration_id IS NOT NULL));
CREATE INDEX IF NOT EXISTS idx_side_sessions_conv ON side_question_sessions(conversation_id);
CREATE INDEX IF NOT EXISTS idx_side_sessions_task ON side_question_sessions(task_id);
CREATE INDEX IF NOT EXISTS idx_side_sessions_exp ON side_question_sessions(exploration_id);
CREATE INDEX IF NOT EXISTS idx_side_sessions_intent ON side_question_sessions(intent_id);
CREATE INDEX IF NOT EXISTS idx_side_sessions_approval ON side_question_sessions(approval_id);

CREATE TABLE IF NOT EXISTS side_question_requests (
    id TEXT PRIMARY KEY,
    ordinal BIGSERIAL UNIQUE,
    session_key TEXT NOT NULL REFERENCES side_question_sessions(session_key) ON DELETE CASCADE,
    generation BIGINT NOT NULL,
    client_id TEXT NOT NULL,
    question TEXT NOT NULL,
    answer TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK(status IN ('running','completed','failed','cancelled','interrupted')),
    error TEXT NOT NULL DEFAULT '',
    model JSONB NOT NULL,
    snapshot_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    sequence BIGINT NOT NULL DEFAULT 0,
    usage JSONB NOT NULL DEFAULT '{}',
    UNIQUE(session_key,generation,client_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_side_request_running ON side_question_requests(session_key) WHERE status='running';
CREATE INDEX IF NOT EXISTS idx_side_requests_history ON side_question_requests(session_key,ordinal DESC);

-- Additive v3 archive fields; old archives restore these as empty objects.
ALTER TABLE side_question_sessions ADD COLUMN IF NOT EXISTS memory JSONB NOT NULL DEFAULT '{}';
ALTER TABLE side_question_requests ADD COLUMN IF NOT EXISTS context_info JSONB NOT NULL DEFAULT '{}';

-- =====================================================================
-- 资产拦截规则（全局黑名单）
-- 独立于 §K 命令拦截(intercept_rules)：intercept_rules 匹配工具名/入参文本，
-- 这张表匹配「目标资产」——全等/模糊的域名·IP·URL 以及 CIDR 网段。
-- 仅存规则；具体的匹配/拦截逻辑在别处实现。
-- kind 七种：
--   exact_domain / exact_ip / exact_url  —— 全等匹配
--   fuzzy_domain / fuzzy_ip / fuzzy_url  —— 模糊匹配
--   cidr                                 —— CIDR 网段
-- =====================================================================
CREATE TABLE IF NOT EXISTS asset_intercept_rules (
    id          BIGSERIAL PRIMARY KEY,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    kind        TEXT NOT NULL CHECK (kind IN (
                    'exact_domain', 'exact_ip', 'exact_url',
                    'fuzzy_domain', 'fuzzy_ip', 'fuzzy_url',
                    'cidr')),
    pattern     TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT '',
    builtin     BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_asset_intercept_enabled ON asset_intercept_rules(enabled);
DROP TRIGGER IF EXISTS trg_asset_intercept_rules_upd ON asset_intercept_rules;
CREATE TRIGGER trg_asset_intercept_rules_upd BEFORE UPDATE ON asset_intercept_rules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- =====================================================================
-- 任务级资产拦截/允许规则
-- 与全局 asset_intercept_rules 同构（kind/pattern/note/enabled），但按 task_id
-- 关联、随任务级联删除；创建任务时录入、任务详情里可编辑。
-- action: 'block'=拦截(禁止测试)  'allow'=允许(白名单)。
-- 执行判定：先按 拦截规则(全局 ∪ 任务block) 匹配，命中即禁止；未命中且该任务存在
-- 启用的 allow 规则时，须命中某条 allow 才放行，否则「不允许测试」。
-- =====================================================================
CREATE TABLE IF NOT EXISTS task_intercept_rules (
    id          BIGSERIAL PRIMARY KEY,
    task_id     BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    action      TEXT NOT NULL DEFAULT 'block' CHECK (action IN ('block','allow')),
    kind        TEXT NOT NULL CHECK (kind IN (
                    'exact_domain', 'exact_ip', 'exact_url',
                    'fuzzy_domain', 'fuzzy_ip', 'fuzzy_url',
                    'cidr')),
    pattern     TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_task_intercept_task ON task_intercept_rules(task_id);
-- 补旧库(本会话早前建过该表、无 action 列)：加列(带 IF NOT EXISTS)。
ALTER TABLE task_intercept_rules ADD COLUMN IF NOT EXISTS action TEXT NOT NULL DEFAULT 'block';
DROP TRIGGER IF EXISTS trg_task_intercept_rules_upd ON task_intercept_rules;
CREATE TRIGGER trg_task_intercept_rules_upd BEFORE UPDATE ON task_intercept_rules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- =====================================================================
-- M. 漏洞 IM 推送
--
-- 三张表刻意分开，核心是**爆炸半径**：写漏洞的那个事务(RecordFindingTx，
-- 持任务行锁)只允许做一次盲 INSERT，不读渠道表、不跑用户的过滤规则。否则
-- 一条配错的 webhook 过滤条件就能污染/中止事务，导致漏洞存不进去。
--
--   notification_channels   渠道实例配置(可变、含凭据、UI 管理)
--   notification_events     事件事实(写漏洞事务内盲插，含渲染快照)
--   notification_deliveries 投递任务(事务外 fan-out 产生，承载状态/重试/批次)
-- =====================================================================

-- 渠道实例：同一 kind 可配任意多个(如「应急群」「日常群」各一个钉钉机器人)。
-- kind 取值由 server 侧白名单校验，不加 CHECK：与 findings.status 同理，
-- 后续加渠道不应要求改表结构。
CREATE TABLE IF NOT EXISTS notification_channels (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL,
    -- dingtalk 钉钉 / feishu 飞书 / wecom 企业微信 / webhook 通用 / telegram / email
    kind         TEXT NOT NULL,
    enabled      BOOLEAN NOT NULL DEFAULT true,
    -- 凭据(明文存储，UI 掩码回显；见 server 侧 maskChannelSecrets)。六种渠道字段差异极大，
    -- 统一 JSONB + Go 侧按 kind 严格校验，避免为每渠道加一堆 NULL 列：
    --   dingtalk {webhook,secret}
    --   feishu   {webhook,secret}
    --   wecom    {webhook}
    --   webhook  {url,method,content_type,headers{},body_template}
    --   telegram {bot_token,chat_id,base_url}
    --   email    {host,port,username,password,from,to[],tls}
    config       JSONB NOT NULL DEFAULT '{}',
    -- 推送时机：realtime 命中即推 / digest 进批次按全局周期汇总成一条。
    mode         TEXT NOT NULL DEFAULT 'realtime',
    -- 过滤条件，字段全部可选(缺省=不过滤)：
    --   min_severity       ''|low|medium|high|critical
    --   task_ids/asset_ids 空数组=不限；非空则须交集非空
    --   vulnclass_include/exclude 关键词数组(大小写不敏感子串)；include 空=全收
    --   on_status_change   bool，仅 realtime 模式有意义
    filter       JSONB NOT NULL DEFAULT '{}',
    -- 每分钟投递上限；0=不限流。默认 20 对齐钉钉/企微官方硬限。
    -- 超限不丢消息，只把投递推迟到下一个 tick。
    rate_per_min INTEGER NOT NULL DEFAULT 20,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
DROP TRIGGER IF EXISTS trg_notification_channels_upd ON notification_channels;
CREATE TRIGGER trg_notification_channels_upd BEFORE UPDATE ON notification_channels
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- 事件事实。由 RecordFindingTx / 状态变更事务**同事务**写入，保证「漏洞落库」
-- 与「推送任务存在」原子一致——不存在提交成功但没入队、消息永久丢失的窗口。
-- snapshot 刻意冗余：漏洞事后会被改名/改级别/改状态，推送内容应反映「事发当时」，
-- 且 fan-out 与渲染不必回查 findings/tasks/assets 多张表。
-- finding 删除后事件不级联删除：与 findings 表「任务删除仍独立留存」的语义一致。
CREATE TABLE IF NOT EXISTS notification_events (
    id         BIGSERIAL PRIMARY KEY,
    -- finding_created | finding_status_changed
    kind       TEXT NOT NULL,
    finding_id BIGINT NOT NULL,
    snapshot   JSONB NOT NULL,
    -- fan-out 幂等标记：dispatcher 按此列取待分派事件，处理完置 true。
    -- 用列而非删行，以便投递历史能回溯到事件。
    fanned_out BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notification_events_pending
    ON notification_events(id) WHERE NOT fanned_out;

-- 投递任务：一条事件 × 一个启用渠道 = 一行。fan-out 在事务外做，所以渠道
-- 后开不会补历史(与 agent_triggers 的「迟开 trigger 不补历史」语义一致，
-- 避免启用渠道时一次性刷屏历史积压)。
-- channel_id 级联删除：渠道配置都没了，其投递历史无意义。
CREATE TABLE IF NOT EXISTS notification_deliveries (
    id          BIGSERIAL PRIMARY KEY,
    event_id    BIGINT NOT NULL REFERENCES notification_events(id) ON DELETE CASCADE,
    channel_id  BIGINT NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    -- pending 待发 / sent 已发 / failed 重试耗尽(可手动重发) / skipped 渠道停用或批次取消
    -- pending 待发 / sending 已被某 dispatcher 领取(租约未到期) / sent 已发 /
    -- failed 重试耗尽或永久失败(可手动重发) / skipped 渠道停用。取值不加 CHECK，
    -- 与 findings.status 同理，由 server 侧白名单校验。
    state       TEXT NOT NULL DEFAULT 'pending',
    attempts    INTEGER NOT NULL DEFAULT 0,
    -- 兼作「下次可领取时间」与「租约到期时间」：领取时把它推到未来即构成租约，
    -- 于是「租约未到期」与「未到重试时间」共用同一个条件表达，不需要额外的
    -- lease_until 列。进程崩溃留下的 sending 行会因租约到期被下一轮重新领取。
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error  TEXT NOT NULL DEFAULT '',
    -- digest 模式同批次共享；realtime 恒为 NULL。整批渲染成一条消息后一起置 sent。
    batch_id    BIGINT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_notification_deliveries_due
    ON notification_deliveries(next_attempt_at) WHERE state='pending';
CREATE INDEX IF NOT EXISTS idx_notification_deliveries_history
    ON notification_deliveries(id DESC);
CREATE INDEX IF NOT EXISTS idx_notification_deliveries_batch
    ON notification_deliveries(batch_id) WHERE batch_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_notification_deliveries_channel
    ON notification_deliveries(channel_id, id DESC);

-- A case collects repeated observations of one defect without rewriting findings.
CREATE TABLE IF NOT EXISTS finding_cases (
    id BIGSERIAL PRIMARY KEY,
    task_id BIGINT REFERENCES tasks(id) ON DELETE SET NULL,
    origin_task_id BIGINT NOT NULL,
    title TEXT NOT NULL,
    reason TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT '',
    severity_reason TEXT NOT NULL DEFAULT '',
    report TEXT NOT NULL DEFAULT '',
    version BIGINT NOT NULL DEFAULT 1,
    report_version BIGINT NOT NULL DEFAULT 0,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS finding_case_members (
    finding_id BIGINT PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    case_id BIGINT NOT NULL REFERENCES finding_cases(id),
    joined_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_finding_case_members_case ON finding_case_members(case_id);
CREATE TABLE IF NOT EXISTS finding_case_events (
    id BIGSERIAL PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES finding_cases(id),
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    finding_ids JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS finding_case_suggestions (
    id BIGSERIAL PRIMARY KEY,
    task_id BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    left_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    right_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    reason TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(left_id,right_id),
    CHECK(left_id < right_id)
);
-- Rejected/detached pairs are a durable human veto, also checked on group unions.
CREATE TABLE IF NOT EXISTS finding_case_blocks (
    left_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    right_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    PRIMARY KEY(left_id,right_id), CHECK(left_id < right_id)
);
CREATE OR REPLACE FUNCTION finding_case_changed() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE cid BIGINT; remaining INTEGER;
BEGIN
    IF TG_TABLE_NAME = 'findings' THEN
        IF OLD IS NOT DISTINCT FROM NEW THEN RETURN NEW; END IF;
        SELECT case_id INTO cid FROM finding_case_members WHERE finding_id=NEW.id;
    ELSE
        cid := OLD.case_id;
    END IF;
    IF cid IS NOT NULL THEN
        UPDATE finding_cases SET version=version+1 WHERE id=cid;
        IF TG_OP='DELETE' THEN
            SELECT count(*) INTO remaining FROM finding_case_members WHERE case_id=cid;
            INSERT INTO finding_case_events(case_id,action,actor,reason,finding_ids)
                VALUES(cid,'member_deleted','system','成员移出或删除',jsonb_build_array(OLD.finding_id));
            IF remaining < 2 THEN
                UPDATE finding_cases SET active=false WHERE id=cid;
                DELETE FROM finding_case_members WHERE case_id=cid;
            END IF;
        END IF;
    END IF;
    RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS finding_case_content_changed ON findings;
CREATE TRIGGER finding_case_content_changed AFTER UPDATE ON findings
FOR EACH ROW EXECUTE FUNCTION finding_case_changed();
DROP TRIGGER IF EXISTS finding_case_member_deleted ON finding_case_members;
CREATE TRIGGER finding_case_member_deleted AFTER DELETE ON finding_case_members
FOR EACH ROW EXECUTE FUNCTION finding_case_changed();
CREATE TABLE IF NOT EXISTS finding_case_review_runs (
    conversation_id BIGINT PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
    task_id BIGINT REFERENCES tasks(id) ON DELETE SET NULL,
    state TEXT NOT NULL DEFAULT 'queued',
    error TEXT NOT NULL DEFAULT ''
);

ALTER TABLE finding_case_review_runs ADD COLUMN IF NOT EXISTS finding_ids JSONB NOT NULL DEFAULT '[]';

ALTER TABLE finding_case_review_runs ADD COLUMN IF NOT EXISTS reviewed_ids JSONB NOT NULL DEFAULT '[]';
ALTER TABLE finding_case_review_runs ADD COLUMN IF NOT EXISTS conclusion JSONB NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS idx_finding_case_reviews_active_task ON finding_case_review_runs(task_id) WHERE state IN ('queued','running');

CREATE TABLE IF NOT EXISTS task_schedule_history (
 id BIGSERIAL PRIMARY KEY,
 schedule_id BIGINT NOT NULL REFERENCES task_schedules(id) ON DELETE CASCADE,
 task_id BIGINT,
 action TEXT NOT NULL,
 success BOOLEAN NOT NULL,
 message TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_schedule_history ON task_schedule_history(schedule_id,id DESC);

-- Task intelligence is separate from shared asset authentication and graph compaction.
CREATE TABLE IF NOT EXISTS task_intelligence (
    id BIGSERIAL PRIMARY KEY,
    task_id BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    node_id BIGINT REFERENCES exploration_nodes(id) ON DELETE SET NULL,
    kind TEXT NOT NULL CHECK (kind IN ('credential','lead','sensitive_data')),
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT '',
    confidence TEXT NOT NULL CHECK (confidence IN ('observed','inferred')),
    status TEXT NOT NULL,
    asset_ids JSONB NOT NULL DEFAULT '[]',
    worker TEXT NOT NULL DEFAULT '',
    fingerprint TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(task_id,kind,fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_task_intelligence_task ON task_intelligence(task_id,id DESC);
CREATE INDEX IF NOT EXISTS idx_task_intelligence_assets ON task_intelligence USING gin(asset_ids);

-- Optional derived credential presentation; raw intelligence remains authoritative.
ALTER TABLE task_intelligence ADD COLUMN IF NOT EXISTS credential_analysis JSONB;

-- =====================================================================
-- Jingwei additions: POC template library (nuclei YAML)
-- 模板原始 YAML 存 content；检索字段与 YAML 解析结果同步维护。
-- =====================================================================
CREATE TABLE IF NOT EXISTS poc_templates (
    id           BIGSERIAL PRIMARY KEY,
    template_id  TEXT NOT NULL,
    name         TEXT NOT NULL,
    severity     TEXT NOT NULL DEFAULT 'info',
    protocol     TEXT NOT NULL DEFAULT '',
    cve_id       TEXT NOT NULL DEFAULT '',
    cwe_id       TEXT NOT NULL DEFAULT '',
    cvss_score   DOUBLE PRECISION,
    tags         JSONB NOT NULL DEFAULT '[]',
    author       TEXT NOT NULL DEFAULT '',
    description  TEXT NOT NULL DEFAULT '',
    refs         JSONB NOT NULL DEFAULT '[]',
    source       TEXT NOT NULL DEFAULT 'manual',
    source_url   TEXT NOT NULL DEFAULT '',
    content      TEXT NOT NULL,
    digest       TEXT NOT NULL DEFAULT '',
    enabled      BOOLEAN NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (template_id)
);
CREATE INDEX IF NOT EXISTS idx_poc_templates_severity ON poc_templates(severity);
CREATE INDEX IF NOT EXISTS idx_poc_templates_source ON poc_templates(source);
CREATE INDEX IF NOT EXISTS idx_poc_templates_enabled ON poc_templates(enabled);
CREATE INDEX IF NOT EXISTS idx_poc_templates_name ON poc_templates(lower(name));
CREATE INDEX IF NOT EXISTS idx_poc_templates_tags ON poc_templates USING gin(tags);
DROP TRIGGER IF EXISTS trg_poc_templates_upd ON poc_templates;
CREATE TRIGGER trg_poc_templates_upd BEFORE UPDATE ON poc_templates
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- =====================================================================
-- Jingwei additions: LLM-free automated scan tasks
-- 目标解析 → 端口/服务发现 → HTTP 指纹 → POC 匹配 → nuclei 扫描。
-- 不依赖 LLM；发现的 Web 资产写入全局资产库，命中结果可写入 findings。
-- =====================================================================
CREATE TABLE IF NOT EXISTS scan_tasks (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT NOT NULL DEFAULT '',
    targets         JSONB NOT NULL DEFAULT '[]',
    mode            TEXT NOT NULL DEFAULT 'auto',
    poc_ids         JSONB NOT NULL DEFAULT '[]',
    ports           TEXT NOT NULL DEFAULT 'top100',
    min_severity    TEXT NOT NULL DEFAULT '',
    fingerprint     BOOLEAN NOT NULL DEFAULT true,
    create_findings BOOLEAN NOT NULL DEFAULT true,
    rate_limit      INTEGER NOT NULL DEFAULT 50,
    concurrency     INTEGER NOT NULL DEFAULT 25,
    timeout_seconds INTEGER NOT NULL DEFAULT 600,
    status          TEXT NOT NULL DEFAULT 'queued',
    stage           TEXT NOT NULL DEFAULT 'queued',
    progress        JSONB NOT NULL DEFAULT '{}',
    summary         JSONB NOT NULL DEFAULT '{}',
    log             TEXT NOT NULL DEFAULT '',
    error           TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_scan_tasks_created ON scan_tasks(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_tasks_status ON scan_tasks(status, id);

-- 漏扫可选：命中后尝试 Webshell 注入。参数（上传/落地路径、类型、密码）存 JSONB。
ALTER TABLE scan_tasks ADD COLUMN IF NOT EXISTS webshell_inject BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE scan_tasks ADD COLUMN IF NOT EXISTS webshell_params JSONB NOT NULL DEFAULT '{}';

-- 可选代理：http(s):// 或 socks5(h)://，整轮扫描（发现/nuclei/弱口令/深度利用子任务）都经它出站。
ALTER TABLE scan_tasks ADD COLUMN IF NOT EXISTS proxy TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS scan_task_assets (
    scan_task_id BIGINT NOT NULL REFERENCES scan_tasks(id) ON DELETE CASCADE,
    asset_id     BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    asset_type   TEXT NOT NULL DEFAULT 'service',
    host         TEXT NOT NULL DEFAULT '',
    url          TEXT NOT NULL DEFAULT '',
    note         TEXT NOT NULL DEFAULT '',
    status_code  INTEGER,
    page_title   TEXT NOT NULL DEFAULT '',
    technologies JSONB NOT NULL DEFAULT '[]',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scan_task_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_scan_task_assets_task ON scan_task_assets(scan_task_id);

CREATE TABLE IF NOT EXISTS scan_task_results (
    id           BIGSERIAL PRIMARY KEY,
    scan_task_id BIGINT NOT NULL REFERENCES scan_tasks(id) ON DELETE CASCADE,
    finding_id   BIGINT REFERENCES findings(id) ON DELETE SET NULL,
    template_id  TEXT NOT NULL DEFAULT '',
    name         TEXT NOT NULL DEFAULT '',
    severity     TEXT NOT NULL DEFAULT '',
    host         TEXT NOT NULL DEFAULT '',
    matched_at   TEXT NOT NULL DEFAULT '',
    type         TEXT NOT NULL DEFAULT '',
    curl_command TEXT NOT NULL DEFAULT '',
    extracted    JSONB NOT NULL DEFAULT '[]',
    raw          JSONB NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scan_task_id, template_id, matched_at)
);
CREATE INDEX IF NOT EXISTS idx_scan_task_results_task ON scan_task_results(scan_task_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_scan_task_results_finding ON scan_task_results(finding_id) WHERE finding_id IS NOT NULL;

-- 运行中的任务在进程重启后不会自动续跑：启动时标记为 failed，避免半截状态卡住。
ALTER TABLE scan_tasks ADD COLUMN IF NOT EXISTS log TEXT NOT NULL DEFAULT '';

-- D5 断点续扫：把「这一轮要扫什么」和「哪一片扫完了」落库。
-- plan 钉住目标、模板 ID 与其内容摘要、分片参数与发现阶段上下文（服务/应用系统），
-- 并带一个 phase（poc → postprocess → done）标出中断发生在哪一段；
-- shards 每行是「一段模板 × 一组目标」，done 的不再执行，failed/未开始的在续扫时重试。
-- 布局与 plan 不一致（POC 被改动、目标变了）时续扫直接拒，绝不把半旧半新的结果拼成一片。
ALTER TABLE scan_tasks ADD COLUMN IF NOT EXISTS plan JSONB NOT NULL DEFAULT '{}';
ALTER TABLE scan_tasks ADD COLUMN IF NOT EXISTS resume_requested BOOLEAN NOT NULL DEFAULT false;
CREATE TABLE IF NOT EXISTS scan_task_shards (
    id           BIGSERIAL PRIMARY KEY,
    scan_task_id BIGINT NOT NULL REFERENCES scan_tasks(id) ON DELETE CASCADE,
    ordinal      INT NOT NULL,
    chunk        INT NOT NULL DEFAULT 0,         -- 模板分片编号
    target       TEXT NOT NULL DEFAULT '',       -- 本片的目标（多个以逗号连接）
    templates    INT NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'pending',  -- pending | done | failed | skipped
    results      INT NOT NULL DEFAULT 0,
    error        TEXT NOT NULL DEFAULT '',
    started_at   TIMESTAMPTZ,
    finished_at  TIMESTAMPTZ,
    UNIQUE (scan_task_id, ordinal)
);
-- 1.6.0 开发期间建过分片表但没有 chunk/target 两列（布局校验需要它们），补齐。
ALTER TABLE scan_task_shards ADD COLUMN IF NOT EXISTS chunk INT NOT NULL DEFAULT 0;
ALTER TABLE scan_task_shards ADD COLUMN IF NOT EXISTS target TEXT NOT NULL DEFAULT '';

-- =====================================================================
-- Jingwei additions: 深度利用（漏洞验证 / 漏洞利用 / WAF 绕过 / Webshell）
-- 全部走异步任务模型，任务与产物分表存储，页面按任务维度回看。
-- =====================================================================
CREATE TABLE IF NOT EXISTS deep_tasks (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT NOT NULL DEFAULT '',
    kind            TEXT NOT NULL DEFAULT 'verify',
    target          TEXT NOT NULL DEFAULT '',
    params          JSONB NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'queued',
    stage           TEXT NOT NULL DEFAULT 'queued',
    progress        JSONB NOT NULL DEFAULT '{}',
    summary         JSONB NOT NULL DEFAULT '{}',
    log             TEXT NOT NULL DEFAULT '',
    error           TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_deep_tasks_created ON deep_tasks(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_deep_tasks_status ON deep_tasks(status, id);
CREATE INDEX IF NOT EXISTS idx_deep_tasks_kind ON deep_tasks(kind, id DESC);

-- 自动利用流水线：深度任务可回指发起它的漏扫任务，并标记为自动创建。
ALTER TABLE deep_tasks ADD COLUMN IF NOT EXISTS scan_task_id BIGINT REFERENCES scan_tasks(id) ON DELETE CASCADE;
ALTER TABLE deep_tasks ADD COLUMN IF NOT EXISTS auto_run BOOLEAN NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS idx_deep_tasks_scan ON deep_tasks(scan_task_id, id);

CREATE TABLE IF NOT EXISTS exploit_records (
    id           BIGSERIAL PRIMARY KEY,
    task_id      BIGINT REFERENCES deep_tasks(id) ON DELETE CASCADE,
    mode         TEXT NOT NULL DEFAULT 'verify',
    template_id  TEXT NOT NULL DEFAULT '',
    name         TEXT NOT NULL DEFAULT '',
    severity     TEXT NOT NULL DEFAULT '',
    target       TEXT NOT NULL DEFAULT '',
    verdict      TEXT NOT NULL DEFAULT '',
    status_code  INTEGER,
    request      TEXT NOT NULL DEFAULT '',
    response     TEXT NOT NULL DEFAULT '',
    extracted    JSONB NOT NULL DEFAULT '[]',
    curl_command TEXT NOT NULL DEFAULT '',
    evidence     TEXT NOT NULL DEFAULT '',
    elapsed_ms   INTEGER NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_exploit_records_task ON exploit_records(task_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_exploit_records_target ON exploit_records(target);

CREATE TABLE IF NOT EXISTS waf_bypass_results (
    id           BIGSERIAL PRIMARY KEY,
    task_id      BIGINT REFERENCES deep_tasks(id) ON DELETE CASCADE,
    target       TEXT NOT NULL DEFAULT '',
    waf_detected BOOLEAN NOT NULL DEFAULT false,
    waf_vendor   TEXT NOT NULL DEFAULT '',
    variant      TEXT NOT NULL DEFAULT '',
    variant_desc TEXT NOT NULL DEFAULT '',
    method       TEXT NOT NULL DEFAULT '',
    path         TEXT NOT NULL DEFAULT '',
    status_code  INTEGER,
    resp_length  INTEGER NOT NULL DEFAULT 0,
    verdict      TEXT NOT NULL DEFAULT '',
    note         TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_waf_bypass_results_task ON waf_bypass_results(task_id, id);
-- D3（1.6.0）：WAF 绕过记录补齐「可量化差异」字段——基线是否拦截、识别到的拦截特征、
-- 第几发、停止原因、整轮最终结论，便于把「第一发就过 / 被拦后第 n 发过 / 预算内全部被拦」
-- 三种形态跑成数字，而不是只留一堆逐条判定。
ALTER TABLE waf_bypass_results ADD COLUMN IF NOT EXISTS attempt INTEGER NOT NULL DEFAULT 0;
ALTER TABLE waf_bypass_results ADD COLUMN IF NOT EXISTS stop_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_bypass_results ADD COLUMN IF NOT EXISTS block_feature TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_bypass_results ADD COLUMN IF NOT EXISTS final_verdict TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_bypass_results ADD COLUMN IF NOT EXISTS baseline_blocked BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS webshells (
    id            BIGSERIAL PRIMARY KEY,
    name          TEXT NOT NULL DEFAULT '',
    url           TEXT NOT NULL DEFAULT '',
    shell_type    TEXT NOT NULL DEFAULT 'php',
    password      TEXT NOT NULL DEFAULT '',
    target        TEXT NOT NULL DEFAULT '',
    source        TEXT NOT NULL DEFAULT 'manual',
    task_id       BIGINT REFERENCES deep_tasks(id) ON DELETE SET NULL,
    status        TEXT NOT NULL DEFAULT 'unknown',
    note          TEXT NOT NULL DEFAULT '',
    last_checked  TIMESTAMPTZ,
    last_output   TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_webshells_created ON webshells(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_webshells_target ON webshells(target);
-- 加密 webshell v2：密钥只存在于载荷源码里，平台侧加密落盘在 secret 中；
-- carrier 是随机请求载体名（随机 HTTP 头或表单字段），payload_sha256 是
-- 最近一次生成/投放载荷的指纹，key_version 随轮换递增。
ALTER TABLE webshells ADD COLUMN IF NOT EXISTS protocol TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE webshells ADD COLUMN IF NOT EXISTS secret TEXT NOT NULL DEFAULT '';
ALTER TABLE webshells ADD COLUMN IF NOT EXISTS carrier TEXT NOT NULL DEFAULT '';
ALTER TABLE webshells ADD COLUMN IF NOT EXISTS payload_sha256 TEXT NOT NULL DEFAULT '';
ALTER TABLE webshells ADD COLUMN IF NOT EXISTS key_version INTEGER NOT NULL DEFAULT 1;
-- os_kind 缓存一次探测的结果：换 POSIX/Windows wrapper 靠的是它，每条命令先探测
-- 一次会把一次交互变成两次往返。故意不存 cwd——目录属于「哪一个交互上下文」而不
-- 属于这个落地文件：一个 webshell 可以绑任意多个内网会话，每个会话已经各自记着
-- cwd（intranet_sessions.cwd），这里再存一份就是同一个目标上的第二个真相。
ALTER TABLE webshells ADD COLUMN IF NOT EXISTS os_kind TEXT NOT NULL DEFAULT '';
-- php_env 存一次投放后探测到的 PHP 运行时环境（版本/SAPI/disable_functions/
-- open_basedir）。选路与「这个壳能不能执行命令」都靠它当证据，探测失败时显式
-- 存 probe_error，而不是留空让人误以为环境干净。
ALTER TABLE webshells ADD COLUMN IF NOT EXISTS php_env JSONB NOT NULL DEFAULT '{}';
DROP TRIGGER IF EXISTS trg_webshells_upd ON webshells;
CREATE TRIGGER trg_webshells_upd BEFORE UPDATE ON webshells
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Java 内存马：由加密 v2 webshell 注入目标 JVM 的常驻组件（filter/servlet/
-- listener/valve/agent）。密钥同样封装后落库，只存在于投放载荷与运行时内存；
-- webshell_id 记录父级落地点，即使内存马地址失效也能通过父 shell 反向清理。
CREATE TABLE IF NOT EXISTS java_memshells (
    id            BIGSERIAL PRIMARY KEY,
    webshell_id   BIGINT REFERENCES webshells(id) ON DELETE SET NULL,
    task_id       BIGINT REFERENCES deep_tasks(id) ON DELETE SET NULL,
    type          TEXT NOT NULL DEFAULT '',
    name          TEXT NOT NULL DEFAULT '',
    path          TEXT NOT NULL DEFAULT '',
    url           TEXT NOT NULL DEFAULT '',
    port          INTEGER NOT NULL DEFAULT 0,
    secret        TEXT NOT NULL DEFAULT '',
    carrier       TEXT NOT NULL DEFAULT '',
    target        TEXT NOT NULL DEFAULT '',
    container     TEXT NOT NULL DEFAULT '',
    servlet_api   TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'unknown',
    note          TEXT NOT NULL DEFAULT '',
    last_checked  TIMESTAMPTZ,
    last_output   TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_memshells_webshell ON java_memshells(webshell_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_memshells_created ON java_memshells(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_memshells_target ON java_memshells(target);
CREATE INDEX IF NOT EXISTS idx_memshells_task ON java_memshells(task_id);
-- E3：投放前探测到的 JVM 版本作为选型证据留存，兼容既有库。
ALTER TABLE java_memshells ADD COLUMN IF NOT EXISTS java_version TEXT NOT NULL DEFAULT '';
DROP TRIGGER IF EXISTS trg_memshells_upd ON java_memshells;
CREATE TRIGGER trg_memshells_upd BEFORE UPDATE ON java_memshells
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- 受管资源台账：JNDI/回调端口、Webshell、隧道等由平台主动创建的资源，
-- 记录归属、TTL 与释放状态，供端口审计和自动清理使用。status：
-- active 使用中 / released 已主动释放 / expired TTL 到期自动回收。
CREATE TABLE IF NOT EXISTS managed_resources (
    id          BIGSERIAL PRIMARY KEY,
    kind        TEXT NOT NULL DEFAULT '',
    name        TEXT NOT NULL DEFAULT '',
    endpoint    TEXT NOT NULL DEFAULT '',
    target      TEXT NOT NULL DEFAULT '',
    owner       TEXT NOT NULL DEFAULT '',
    task_id     BIGINT,
    status      TEXT NOT NULL DEFAULT 'active',
    expires_at  TIMESTAMPTZ,
    released_at TIMESTAMPTZ,
    metadata    JSONB NOT NULL DEFAULT '{}',
    note        TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_managed_resources_status ON managed_resources(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_managed_resources_task ON managed_resources(task_id);
CREATE INDEX IF NOT EXISTS idx_managed_resources_kind ON managed_resources(kind, id DESC);
-- 同一类资源同一端点同时只允许一条活动记录：重复发布会刷新 TTL/归属而不是堆叠。
CREATE UNIQUE INDEX IF NOT EXISTS idx_managed_resources_active_endpoint
    ON managed_resources(kind, endpoint) WHERE status = 'active';
DROP TRIGGER IF EXISTS trg_managed_resources_upd ON managed_resources;
CREATE TRIGGER trg_managed_resources_upd BEFORE UPDATE ON managed_resources
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- 内网两阶段 MVP：逻辑会话(webshell 复用) → 隧道生命周期 → 范围审批 → 任务交接。
-- 会话不驻留进程：每次 exec 通过已登记 webshell 执行，cwd 在平台侧维护。
CREATE TABLE IF NOT EXISTS intranet_sessions (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL DEFAULT '',
    webshell_id BIGINT REFERENCES webshells(id) ON DELETE SET NULL,
    task_id     BIGINT REFERENCES tasks(id) ON DELETE SET NULL,
    host        TEXT NOT NULL DEFAULT '',
    cwd         TEXT NOT NULL DEFAULT '/',
    status      TEXT NOT NULL DEFAULT 'active',
    last_seen   TIMESTAMPTZ,
    metadata    JSONB NOT NULL DEFAULT '{}',
    note        TEXT NOT NULL DEFAULT '',
    transport   TEXT NOT NULL DEFAULT 'webshell',
    ssh_port    INTEGER NOT NULL DEFAULT 0,
    ssh_user    TEXT NOT NULL DEFAULT '',
    ssh_credential_id BIGINT NOT NULL DEFAULT 0,
    ssh_dial_host TEXT NOT NULL DEFAULT '',
    ssh_dial_port INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_intranet_sessions_status ON intranet_sessions(status, id DESC);
CREATE INDEX IF NOT EXISTS idx_intranet_sessions_task ON intranet_sessions(task_id);
DROP TRIGGER IF EXISTS trg_intranet_sessions_upd ON intranet_sessions;
CREATE TRIGGER trg_intranet_sessions_upd BEFORE UPDATE ON intranet_sessions
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
ALTER TABLE intranet_sessions ADD COLUMN IF NOT EXISTS transport TEXT NOT NULL DEFAULT 'webshell';
ALTER TABLE intranet_sessions ADD COLUMN IF NOT EXISTS ssh_port INTEGER NOT NULL DEFAULT 0;
ALTER TABLE intranet_sessions ADD COLUMN IF NOT EXISTS ssh_user TEXT NOT NULL DEFAULT '';
ALTER TABLE intranet_sessions ADD COLUMN IF NOT EXISTS ssh_credential_id BIGINT NOT NULL DEFAULT 0;
ALTER TABLE intranet_sessions ADD COLUMN IF NOT EXISTS ssh_dial_host TEXT NOT NULL DEFAULT '';
ALTER TABLE intranet_sessions ADD COLUMN IF NOT EXISTS ssh_dial_port INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS intranet_session_events (
    id         BIGSERIAL PRIMARY KEY,
    session_id BIGINT NOT NULL REFERENCES intranet_sessions(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL DEFAULT 'exec',
    command    TEXT NOT NULL DEFAULT '',
    output     TEXT NOT NULL DEFAULT '',
    is_error   BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_intranet_events_session ON intranet_session_events(session_id, id DESC);

CREATE TABLE IF NOT EXISTS intranet_tunnels (
    id               BIGSERIAL PRIMARY KEY,
    name             TEXT NOT NULL DEFAULT '',
    session_id       BIGINT REFERENCES intranet_sessions(id) ON DELETE SET NULL,
    task_id          BIGINT REFERENCES tasks(id) ON DELETE SET NULL,
    kind             TEXT NOT NULL DEFAULT 'socks5',
    listen_host      TEXT NOT NULL DEFAULT '127.0.0.1',
    listen_port      INTEGER NOT NULL DEFAULT 0,
    listen_side      TEXT NOT NULL DEFAULT 'target',
    remote_host      TEXT NOT NULL DEFAULT '',
    remote_port      INTEGER NOT NULL DEFAULT 0,
    status           TEXT NOT NULL DEFAULT 'planned',
    deploy_command   TEXT NOT NULL DEFAULT '',
    verify_command   TEXT NOT NULL DEFAULT '',
    teardown_command TEXT NOT NULL DEFAULT '',
    pid              INTEGER,
    evidence         TEXT NOT NULL DEFAULT '',
    note             TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_intranet_tunnels_status ON intranet_tunnels(status, id DESC);
CREATE INDEX IF NOT EXISTS idx_intranet_tunnels_task ON intranet_tunnels(task_id);
DROP TRIGGER IF EXISTS trg_intranet_tunnels_upd ON intranet_tunnels;
CREATE TRIGGER trg_intranet_tunnels_upd BEFORE UPDATE ON intranet_tunnels
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
-- 监听端在哪一侧：chisel client 的 SOCKS/正向监听开在控制端，socat 与 ssh -D/-L
-- 开在目标。没有这个字段时，验证与拆除复核一律在目标上查端口，控制端侧的隧道
-- 永远"验证失败"，台账里的进程信息也按错误的一侧回收。
ALTER TABLE intranet_tunnels ADD COLUMN IF NOT EXISTS listen_side TEXT NOT NULL DEFAULT 'target';

-- 内网新目标的授权申请：人工在 UI 批准后才写入 task_scope；agent 只可提交申请。
CREATE TABLE IF NOT EXISTS intranet_scope_requests (
    id           BIGSERIAL PRIMARY KEY,
    task_id      BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    host         TEXT NOT NULL,
    port         INTEGER NOT NULL DEFAULT 0,
    reason       TEXT NOT NULL DEFAULT '',
    session_id   BIGINT REFERENCES intranet_sessions(id) ON DELETE SET NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    decided_note TEXT NOT NULL DEFAULT '',
    decided_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_intranet_scope_status ON intranet_scope_requests(status, id DESC);
CREATE INDEX IF NOT EXISTS idx_intranet_scope_task ON intranet_scope_requests(task_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_intranet_scope_pending_unique
    ON intranet_scope_requests(task_id, host, port) WHERE status = 'pending';

-- 凭据复用台账：WebCrack 弱口令命中登记于此，内网横向时按目标挑选复用。
-- task_id 可能是 tasks（内网任务）或 scan_tasks 的编号，故不做外键；scan_task_id 明确指向漏扫。
CREATE TABLE IF NOT EXISTS intranet_credentials (
    id           BIGSERIAL PRIMARY KEY,
    host         TEXT NOT NULL,
    port         INTEGER NOT NULL DEFAULT 0,
    protocol     TEXT NOT NULL DEFAULT 'http',
    url          TEXT NOT NULL DEFAULT '',
    username     TEXT NOT NULL,
    password     TEXT NOT NULL,
    source       TEXT NOT NULL DEFAULT 'weakpass',
    task_id      BIGINT,
    scan_task_id BIGINT REFERENCES scan_tasks(id) ON DELETE SET NULL,
    finding_id   BIGINT REFERENCES findings(id) ON DELETE SET NULL,
    status       TEXT NOT NULL DEFAULT 'untested',
    evidence     TEXT NOT NULL DEFAULT '',
    last_used_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (host, username, password)
);
CREATE INDEX IF NOT EXISTS idx_intranet_creds_host ON intranet_credentials(host, id DESC);
CREATE INDEX IF NOT EXISTS idx_intranet_creds_task ON intranet_credentials(task_id) WHERE task_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_intranet_creds_status ON intranet_credentials(status, id DESC);
DROP TRIGGER IF EXISTS trg_intranet_credentials_upd ON intranet_credentials;
CREATE TRIGGER trg_intranet_credentials_upd BEFORE UPDATE ON intranet_credentials
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- 凭据跨主机复用批次（F1）：一次「拿这条凭据试这几台主机」= 一个批次。
-- 每一次尝试都落 attempts，跳过/被拒/报错也记：撤销时要能说清这一批碰过什么，
-- 而不只是「成功了几个」。撤销只删本批新产生的凭据，批次之前就存在的记录不动。
CREATE TABLE IF NOT EXISTS intranet_credential_reuses (
    id            BIGSERIAL PRIMARY KEY,
    credential_id BIGINT NOT NULL,
    task_id       BIGINT NOT NULL DEFAULT 0,
    total         INTEGER NOT NULL DEFAULT 0,
    valid_count   INTEGER NOT NULL DEFAULT 0,
    invalid_count INTEGER NOT NULL DEFAULT 0,
    skipped_count INTEGER NOT NULL DEFAULT 0,
    error_count   INTEGER NOT NULL DEFAULT 0,
    note          TEXT NOT NULL DEFAULT '',
    revoked_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cred_reuses_cred ON intranet_credential_reuses(credential_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_cred_reuses_created ON intranet_credential_reuses(created_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS intranet_credential_reuse_attempts (
    id         BIGSERIAL PRIMARY KEY,
    reuse_id   BIGINT NOT NULL REFERENCES intranet_credential_reuses(id) ON DELETE CASCADE,
    url        TEXT NOT NULL DEFAULT '',
    host       TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL DEFAULT '',
    attempts   INTEGER NOT NULL DEFAULT 0,
    elapsed_ms BIGINT NOT NULL DEFAULT 0,
    error      TEXT NOT NULL DEFAULT '',
    evidence   TEXT NOT NULL DEFAULT '',
    -- 这次尝试新登记出来的凭据；撤销时按它精确回滚，NULL 表示没有新建。
    created_credential_id BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cred_reuse_attempts_reuse ON intranet_credential_reuse_attempts(reuse_id, id);

-- 内网落地物台账：目标侧的一切持久化痕迹（上传文件、计划任务、systemd 服务、
-- SSH 公钥等）。每条记录自带撤销命令与验证命令，撤离时按 id 逆序逐条执行并核验。
-- task_id 与 intranet_sessions 一致，可能是 tasks 或 scan_tasks 的编号，故不做外键。
CREATE TABLE IF NOT EXISTS intranet_artifacts (
    id             BIGSERIAL PRIMARY KEY,
    task_id        BIGINT,
    session_id     BIGINT REFERENCES intranet_sessions(id) ON DELETE SET NULL,
    host           TEXT NOT NULL DEFAULT '',
    kind           TEXT NOT NULL,
    name           TEXT NOT NULL DEFAULT '',
    path           TEXT NOT NULL DEFAULT '',
    description    TEXT NOT NULL DEFAULT '',
    deploy_command TEXT NOT NULL DEFAULT '',
    revoke_command TEXT NOT NULL,
    verify_command TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
    evidence       TEXT NOT NULL DEFAULT '',
    metadata       JSONB NOT NULL DEFAULT '{}',
    revoked_at     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE intranet_artifacts ADD COLUMN IF NOT EXISTS fingerprint TEXT NOT NULL DEFAULT '';
ALTER TABLE intranet_artifacts ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_intranet_artifacts_task ON intranet_artifacts(task_id, status, id DESC);
CREATE INDEX IF NOT EXISTS idx_intranet_artifacts_session ON intranet_artifacts(session_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_intranet_artifacts_host ON intranet_artifacts(host, kind, id DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uq_intranet_artifacts_fingerprint_active
    ON intranet_artifacts(fingerprint) WHERE status='active' AND fingerprint <> '';
CREATE INDEX IF NOT EXISTS idx_intranet_artifacts_expires
    ON intranet_artifacts(expires_at) WHERE status='active' AND expires_at IS NOT NULL;
DROP TRIGGER IF EXISTS trg_intranet_artifacts_upd ON intranet_artifacts;
CREATE TRIGGER trg_intranet_artifacts_upd BEFORE UPDATE ON intranet_artifacts
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- 目标策略拒绝台账（见 db/guard_denials.go）。失败关闭的范围/禁令判定每拒一次记一行，
-- 只记归属与原因类别，不记目标明文以外的大量参数。刻意不设外键：任务删除后仍要能回答
-- 「这一周有多少工具调用是被策略挡掉的」。
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS guard_denials (
    id         BIGSERIAL PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    task_id    BIGINT,
    category   TEXT NOT NULL,
    mode       TEXT NOT NULL DEFAULT 'strict',
    reason     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_guard_denials_task ON guard_denials(task_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_guard_denials_ts ON guard_denials(ts DESC);

-- ---------------------------------------------------------------------------
-- 弱口令检测（界面名）任务与结果，见 db/credscan.go。内部标识保持 credscan。
-- 结果的六态 outcome（hit/deny/unreachable/locked/inconclusive/unsupported）
-- 与 scanner.CredOutcome 一一对应；「少一行＝说谎」这条规矩在存储层同样成立：
-- 每个端点×凭据都要有一行，连不上与没测出来也不能省。
-- 口令与证据都是明文字节：这一列存的是发现本身（报告要能复现），
-- 需要密封复用的凭据在 intranet_credentials，两处的用途不同，别混。
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cred_tasks (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL DEFAULT '',
    targets      JSONB NOT NULL DEFAULT '[]',
    protocols    JSONB NOT NULL DEFAULT '[]',
    options      JSONB NOT NULL DEFAULT '{}',
    dict_profile TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'queued',
    stage        TEXT NOT NULL DEFAULT 'queued',
    progress     JSONB NOT NULL DEFAULT '{}',
    summary      JSONB NOT NULL DEFAULT '{}',
    log          TEXT NOT NULL DEFAULT '',
    error        TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at   TIMESTAMPTZ,
    finished_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_cred_tasks_created ON cred_tasks(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_cred_tasks_status ON cred_tasks(status, id);

CREATE TABLE IF NOT EXISTS cred_results (
    id                 BIGSERIAL PRIMARY KEY,
    task_id            BIGINT NOT NULL REFERENCES cred_tasks(id) ON DELETE CASCADE,
    host               TEXT NOT NULL,
    port               INTEGER NOT NULL,
    protocol           TEXT NOT NULL DEFAULT '',
    protocol_source    TEXT NOT NULL DEFAULT '',
    protocol_confirmed BOOLEAN NOT NULL DEFAULT false,
    params             JSONB NOT NULL DEFAULT '{}',
    username           TEXT NOT NULL DEFAULT '',
    password           TEXT NOT NULL DEFAULT '',
    outcome            TEXT NOT NULL,
    banner             TEXT NOT NULL DEFAULT '',
    evidence           TEXT NOT NULL DEFAULT '',
    tls                BOOLEAN NOT NULL DEFAULT false,
    reason             TEXT NOT NULL DEFAULT '',
    attempts           INTEGER NOT NULL DEFAULT 0,
    elapsed_ms         BIGINT NOT NULL DEFAULT 0,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cred_results_task ON cred_results(task_id, id);
CREATE INDEX IF NOT EXISTS idx_cred_results_outcome ON cred_results(task_id, outcome, id);
CREATE INDEX IF NOT EXISTS idx_cred_results_endpoint ON cred_results(task_id, host, port, id);

-- 操作员导入的弱口令字典（B10）。内置精简字典在代码里（scanner/credscan_dict.go），
-- 这张表只存导入档；cred_tasks.dict_profile 记名字，报告才能说清用的是哪本字典。
CREATE TABLE IF NOT EXISTS cred_dicts (
    name       TEXT PRIMARY KEY,
    entries    TEXT NOT NULL,
    entry_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- G2：落地物到期前的主动告警标记。告警发出后写入该列，避免每个扫描周期
-- 重复推送同一条；落地物撤销/删除后该行随之消失。
ALTER TABLE intranet_artifacts ADD COLUMN IF NOT EXISTS expiry_notified_at TIMESTAMPTZ;

-- F3：内网信息收集脚本的运行台账。每条脚本一次执行一行，stdout 与结构化
-- 提取结果都落库——报告与横向决策要用的是结构化的端口/账号/计划任务，
-- 而不是一大段需要人肉阅读的终端输出。
CREATE TABLE IF NOT EXISTS intranet_script_runs (
    id         BIGSERIAL PRIMARY KEY,
    session_id BIGINT REFERENCES intranet_sessions(id) ON DELETE SET NULL,
    task_id    BIGINT,
    script_id  TEXT NOT NULL,
    name       TEXT NOT NULL DEFAULT '',
    os         TEXT NOT NULL DEFAULT '',
    command    TEXT NOT NULL DEFAULT '',
    exit_code  INTEGER,
    status     TEXT NOT NULL DEFAULT 'done',
    output     TEXT NOT NULL DEFAULT '',
    parsed     JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_intranet_script_runs_session ON intranet_script_runs(session_id, id DESC);

-- F4：客户授权清单（一等公民）。启用的清单存在时，agent 与任务的目标判定
-- 必须落在某条有效授权内且不命中其排除项；没有任何清单时保持历史行为（不强制）。
CREATE TABLE IF NOT EXISTS authorizations (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    targets    JSONB NOT NULL DEFAULT '[]'::jsonb,
    exclusions JSONB NOT NULL DEFAULT '[]'::jsonb,
    starts_at  TIMESTAMPTZ,
    ends_at    TIMESTAMPTZ,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    note       TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_authorizations_active ON authorizations(enabled, ends_at);

-- 授权清单的数组列最初建成 TEXT[]，pgx 在文本协议下把它读成 "{a,b}" 字面量，
-- 扫不进 []string（读一次错一次）。改成与其余数组列一致的 JSONB。
-- 已经建过表的库就地转换，只在列还是数组类型时执行。
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = current_schema()
                 AND table_name = 'authorizations' AND column_name = 'targets' AND data_type = 'ARRAY') THEN
        -- 顺序有讲究：先 DROP DEFAULT。改列类型时 Postgres 会把列上**原有的**默认值
        -- 重新按新类型校验，'{}'::text[] 转不成 jsonb，直接 ALTER TYPE 会报
        -- 「default for column "targets" cannot be cast automatically」。
        -- 另外每条都用 EXECUTE：schema.sql 整份一次送进服务端，普通语句会按改动前的
        -- 表结构统一解析，后面的 SET DEFAULT 同样会被旧类型卡住。
        EXECUTE 'ALTER TABLE authorizations ALTER COLUMN targets DROP DEFAULT';
        EXECUTE 'ALTER TABLE authorizations ALTER COLUMN exclusions DROP DEFAULT';
        EXECUTE 'ALTER TABLE authorizations ALTER COLUMN targets TYPE JSONB USING to_jsonb(targets)';
        EXECUTE 'ALTER TABLE authorizations ALTER COLUMN exclusions TYPE JSONB USING to_jsonb(exclusions)';
        EXECUTE 'ALTER TABLE authorizations ALTER COLUMN targets SET DEFAULT ''[]''::jsonb';
        EXECUTE 'ALTER TABLE authorizations ALTER COLUMN exclusions SET DEFAULT ''[]''::jsonb';
    END IF;
END $$;

-- C3：子域名枚举的任务与结果。
--
-- 结果表只回答「这一轮枚举出了什么」，资产的真相仍在 assets 里（子域名行 + 由 A/AAAA
-- 顺带登记的 IP 行）。两处分开是有意的：把发现直接写成资产、不给任务台账，用户就
-- 无法回答「这些子域名是哪一轮、用什么方式得到的」；只留台账不写资产，拓扑图与端口
-- 探测就拿不到东西，等于让人手工搬运。
CREATE TABLE IF NOT EXISTS subdomain_tasks (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL DEFAULT '',
    targets      JSONB NOT NULL DEFAULT '[]',
    options      JSONB NOT NULL DEFAULT '{}',
    status       TEXT NOT NULL DEFAULT 'queued',
    stage        TEXT NOT NULL DEFAULT 'queued',
    progress     JSONB NOT NULL DEFAULT '{}',
    summary      JSONB NOT NULL DEFAULT '{}',
    log          TEXT NOT NULL DEFAULT '',
    error        TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at   TIMESTAMPTZ,
    finished_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_subdomain_tasks_created ON subdomain_tasks(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_subdomain_tasks_status ON subdomain_tasks(status, id);

CREATE TABLE IF NOT EXISTS subdomain_results (
    id         BIGSERIAL PRIMARY KEY,
    task_id    BIGINT NOT NULL REFERENCES subdomain_tasks(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    root       TEXT NOT NULL DEFAULT '',
    source     TEXT NOT NULL DEFAULT '',
    records    JSONB NOT NULL DEFAULT '[]',
    ips        JSONB NOT NULL DEFAULT '[]',
    -- 与泛解析基线一致的命中（只在操作员选择保留时入库）：标出来，别和真子域名混为一谈。
    wildcard   BOOLEAN NOT NULL DEFAULT false,
    -- 写入资产台账后的子域名资产编号；写失败时为 NULL，报告要能说「这条没进资产」。
    asset_id   BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (task_id, name)
);
CREATE INDEX IF NOT EXISTS idx_subdomain_results_task ON subdomain_results(task_id, id);
CREATE INDEX IF NOT EXISTS idx_subdomain_results_asset ON subdomain_results(asset_id);
