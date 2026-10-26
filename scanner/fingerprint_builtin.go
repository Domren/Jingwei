package scanner

import (
	"net/http"
	"sort"
	"strings"
)

// fpRule describes one web technology signature.
type fpRule struct {
	name    string
	tags    []string
	headers map[string][]string // key -> lowercase value substrings; nil values mean header presence
	cookies []string
	body    []string
}

var fpRules = []fpRule{
	{name: "Nginx", tags: []string{"nginx"}, headers: map[string][]string{"server": {"nginx"}}},
	{name: "OpenResty", tags: []string{"openresty", "nginx"}, headers: map[string][]string{"server": {"openresty"}}},
	{name: "Apache HTTP Server", tags: []string{"apache", "httpd"}, headers: map[string][]string{"server": {"apache"}}},
	{name: "Microsoft IIS", tags: []string{"iis", "microsoft"}, headers: map[string][]string{"server": {"microsoft-iis"}}},
	{name: "Tomcat", tags: []string{"tomcat", "apache"}, headers: map[string][]string{"server": {"tomcat"}}, body: []string{"apache tomcat"}},
	{name: "Jetty", tags: []string{"jetty"}, headers: map[string][]string{"server": {"jetty"}}},
	{name: "Undertow", tags: []string{"undertow"}, headers: map[string][]string{"server": {"undertow"}}},
	{name: "WildFly", tags: []string{"wildfly", "jboss"}, headers: map[string][]string{"server": {"wildfly", "jboss"}}, body: []string{"jboss"}},
	{name: "WebLogic", tags: []string{"weblogic", "oracle"}, body: []string{"weblogic"}, cookies: []string{"adminconsolesession"}},
	{name: "WebSphere", tags: []string{"websphere", "ibm"}, headers: map[string][]string{"server": {"websphere"}}, body: []string{"websphere"}},
	{name: "GlassFish", tags: []string{"glassfish"}, headers: map[string][]string{"server": {"glassfish"}}},
	{name: "Spring Boot", tags: []string{"spring", "springboot"}, headers: map[string][]string{"x-application-context": nil}, body: []string{"whitelabel error page", "spring boot"}},
	{name: "Apache Shiro", tags: []string{"shiro", "apache"}, cookies: []string{"rememberme="}},
	{name: "Fastjson", tags: []string{"fastjson", "alibaba"}, body: []string{"fastjson"}},
	{name: "ThinkPHP", tags: []string{"thinkphp", "php"}, headers: map[string][]string{"x-powered-by": {"thinkphp"}}, body: []string{"thinkphp"}},
	{name: "Laravel", tags: []string{"laravel", "php"}, cookies: []string{"laravel_session"}},
	{name: "PHP", tags: []string{"php"}, headers: map[string][]string{"x-powered-by": {"php"}}},
	{name: "ASP.NET", tags: []string{"aspnet", "dotnet", "iis"}, headers: map[string][]string{"x-powered-by": {"asp.net"}, "x-aspnet-version": nil}},
	{name: "Kestrel", tags: []string{"kestrel", "aspnet", "dotnet"}, headers: map[string][]string{"server": {"kestrel"}}},
	{name: "WordPress", tags: []string{"wordpress", "php"}, body: []string{"wp-content", "wp-includes", "wordpress"}},
	{name: "Drupal", tags: []string{"drupal", "php"}, headers: map[string][]string{"x-generator": {"drupal"}}, body: []string{"drupal.settings"}},
	{name: "Joomla", tags: []string{"joomla", "php"}, body: []string{"joomla"}},
	{name: "phpMyAdmin", tags: []string{"phpmyadmin", "php"}, body: []string{"phpmyadmin"}},
	{name: "Grafana", tags: []string{"grafana"}, cookies: []string{"grafana_session"}, body: []string{"grafana"}},
	{name: "Prometheus", tags: []string{"prometheus"}, body: []string{"prometheus"}},
	{name: "Kibana", tags: []string{"kibana", "elastic"}, body: []string{"kibana"}},
	{name: "Elasticsearch", tags: []string{"elasticsearch", "elastic"}, body: []string{"cluster_name", "lucene_version"}},
	{name: "Jenkins", tags: []string{"jenkins"}, headers: map[string][]string{"x-jenkins": nil}, body: []string{"jenkins"}},
	{name: "GitLab", tags: []string{"gitlab"}, body: []string{"gitlab"}},
	{name: "Zabbix", tags: []string{"zabbix"}, body: []string{"zabbix"}},
	{name: "Confluence", tags: []string{"confluence", "atlassian"}, body: []string{"confluence"}},
	{name: "Jira", tags: []string{"jira", "atlassian"}, body: []string{"jira"}},
	{name: "Nacos", tags: []string{"nacos", "alibaba"}, body: []string{"nacos"}},
	{name: "Apache Druid", tags: []string{"druid", "apache"}, body: []string{"druid"}},
	{name: "Swagger UI", tags: []string{"swagger"}, body: []string{"swagger-ui", "swagger ui"}},
	{name: "Next.js", tags: []string{"nextjs", "react"}, headers: map[string][]string{"x-nextjs": nil}, body: []string{"__next", "/_next/static"}},
	{name: "React", tags: []string{"react"}, body: []string{"data-reactroot", "react.development", "react.production"}},
	{name: "Vue.js", tags: []string{"vue"}, body: []string{"data-v-", "__vue__", "vue.js"}},
	{name: "jQuery", tags: []string{"jquery"}, body: []string{"jquery"}},
	{name: "Bootstrap", tags: []string{"bootstrap"}, body: []string{"bootstrap"}},
	{name: "Cloudflare", tags: []string{"cloudflare"}, headers: map[string][]string{"cf-ray": nil, "server": {"cloudflare"}}},
	{name: "Akamai", tags: []string{"akamai"}, headers: map[string][]string{"server": {"akamaighost"}}},
	{name: "Caddy", tags: []string{"caddy"}, headers: map[string][]string{"server": {"caddy"}}},
	{name: "Envoy", tags: []string{"envoy"}, headers: map[string][]string{"server": {"envoy"}}},
	{name: "Istio", tags: []string{"istio", "envoy"}, headers: map[string][]string{"server": {"istio-envoy"}}},
	{name: "MinIO", tags: []string{"minio"}, headers: map[string][]string{"server": {"minio"}}},
	{name: "Harbor", tags: []string{"harbor"}, body: []string{"harbor"}},
	{name: "RabbitMQ", tags: []string{"rabbitmq"}, body: []string{"rabbitmq management"}},
	{name: "Kubernetes", tags: []string{"kubernetes", "k8s"}, body: []string{"gitversion"}},
	{name: "Docker Registry", tags: []string{"docker", "registry"}, headers: map[string][]string{"docker-distribution-api-version": nil}},
	{name: "SonarQube", tags: []string{"sonarqube"}, body: []string{"sonarqube"}},
	{name: "ActiveMQ", tags: []string{"activemq"}, body: []string{"activemq"}},
	{name: "Solr", tags: []string{"solr"}, body: []string{"solr"}},
	{name: "Hadoop", tags: []string{"hadoop"}, body: []string{"hadoop"}},
	{name: "Flask", tags: []string{"flask", "python"}, headers: map[string][]string{"server": {"werkzeug"}}},
	{name: "Django", tags: []string{"django", "python"}, cookies: []string{"csrftoken", "django_language"}},
	{name: "FastAPI", tags: []string{"fastapi", "python"}, headers: map[string][]string{"server": {"uvicorn"}}},
	{name: "Ruby on Rails", tags: []string{"rails", "ruby"}, headers: map[string][]string{"x-powered-by": {"phusion passenger"}, "server": {"puma"}}},
}

// DetectTechnologies matches response headers/cookies/body against the curated
// and embedded signature libraries.
func DetectTechnologies(h http.Header, body string) []string {
	return finalizeTechHits(detectPageHits(h, body, ""))
}

// DetectTechnologiesForURL additionally uses URL-based signatures.
func DetectTechnologiesForURL(h http.Header, body, rawURL string) []string {
	return finalizeTechHits(detectPageHits(h, body, rawURL))
}

func fpMatch(rule fpRule, h http.Header, cookies, body string) bool {
	for key, values := range rule.headers {
		hv := strings.ToLower(strings.Join(h.Values(key), " "))
		if hv == "" {
			continue
		}
		if len(values) == 0 {
			return true
		}
		for _, v := range values {
			if strings.Contains(hv, v) {
				return true
			}
		}
	}
	for _, c := range rule.cookies {
		if strings.Contains(cookies, c) {
			return true
		}
	}
	for _, b := range rule.body {
		if strings.Contains(body, b) {
			return true
		}
	}
	return false
}

// TechnologyAliases returns normalized tokens used for POC tag matching.
// Latin tokens cover English product names; the vendor table maps common
// Chinese product names (which normToken would reduce to "oa" or nothing) to
// the English tags used by the template library.
func TechnologyAliases(tech string) []string {
	raw := strings.TrimSpace(tech)
	if raw == "" {
		return nil
	}
	out := make([]string, 0, 8)
	if t := normToken(raw); len(t) >= 2 && !genericAliasToken[t] {
		out = append(out, t)
	}
	for _, tok := range latinAliasTokens(raw) {
		if !genericAliasToken[tok] {
			out = append(out, tok)
		}
	}
	lower := strings.ToLower(raw)
	for _, vendor := range cnVendorAliases {
		if strings.Contains(lower, vendor.needle) {
			out = append(out, vendor.aliases...)
		}
	}
	return dedupeStrings(out)
}

var genericAliasToken = map[string]bool{
	"oa": true, "cms": true, "erp": true, "crm": true, "web": true, "www": true,
	"http": true, "https": true, "server": true, "servers": true, "service": true,
	"services": true, "system": true, "systems": true, "platform": true, "portal": true,
	"admin": true, "login": true, "network": true, "security": true, "database": true,
	"db": true, "framework": true, "panel": true, "other": true, "ai": true, "app": true,
	"application": true, "tool": true, "tools": true, "devtool": true, "monitoring": true,
	"cloud": true, "product": true, "products": true, "device": true, "devices": true,
	"router": true, "routers": true, "camera": true, "cameras": true, "printer": true,
	"printers": true, "wireless": true, "firewall": true, "vpn": true, "sslvpn": true,
	"waf": true, "ui": true, "ip": true, "mail": true, "webmail": true, "cdn": true,
	"management": true, "manager": true, "main": true, "default": true, "index": true,
	"content": true, "user": true, "users": true, "info": true, "data": true,
	"java": true, "php": true, "python": true, "ruby": true, "node": true,
	"nodejs": true, "js": true, "javascript": true, "html": true, "css": true,
	"asp": true, "aspx": true, "jsp": true, "go": true, "golang": true, "net": true,
	"email": true, "console": true, "home": true, "page": true, "main page": true,
	"base": true, "client": true, "core": true, "engine": true, "edition": true,
	"suite": true, "office": true, "desktop": true, "worker": true, "standard": true,
	"professional": true, "enterprise": true, "business": true, "community": true,
}

func latinAliasTokens(s string) []string {
	raw := make([]string, 0, 4)
	var cur []rune
	flush := func() {
		if len(cur) == 0 {
			return
		}
		tok := string(cur)
		raw = append(raw, tok)
		for _, part := range splitCamelToken(tok) {
			if part != tok {
				raw = append(raw, part)
			}
		}
		cur = cur[:0]
	}
	for _, r := range s {
		if r < 128 && ((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			cur = append(cur, r)
		} else {
			flush()
		}
	}
	flush()
	out := make([]string, 0, len(raw))
	for _, tok := range raw {
		tok = strings.ToLower(tok)
		if len(tok) >= 3 {
			out = append(out, tok)
		}
	}
	return out
}

func splitCamelToken(tok string) []string {
	out := make([]string, 0, 3)
	start := 0
	for i := 1; i < len(tok); i++ {
		prev, cur := tok[i-1], tok[i]
		if (prev >= 'a' && prev <= 'z' && cur >= 'A' && cur <= 'Z') ||
			(prev >= '0' && prev <= '9' && cur >= 'A' && cur <= 'Z') {
			out = append(out, strings.ToLower(tok[start:i]))
			start = i
		}
	}
	out = append(out, strings.ToLower(tok[start:]))
	return out
}

var cnVendorAliases = []struct {
	needle  string
	aliases []string
}{
	{"致远", []string{"seeyon", "seeyon-oa", "zhiyuan"}},
	{"泛微", []string{"weaver", "ecology", "e-cology", "e-office", "e-mobile"}},
	{"通达", []string{"tongda", "tongdaoa"}},
	{"蓝凌", []string{"landray", "landrayoa"}},
	{"金和", []string{"jinher"}},
	{"红帆", []string{"ioffice"}},
	{"华天", []string{"huatian"}},
	{"九思", []string{"jiusi"}},
	{"万户", []string{"wanhu"}},
	{"用友", []string{"yonyou", "ufida", "yonyou-nc", "yonyou-u8"}},
	{"金蝶", []string{"kingdee", "apusic", "eas"}},
	{"帆软", []string{"fanruan", "finereport"}},
	{"广联达", []string{"glodon"}},
	{"明源", []string{"mysoft"}},
	{"管家婆", []string{"grasp"}},
	{"深信服", []string{"sangfor"}},
	{"天融信", []string{"topsec"}},
	{"启明星辰", []string{"venustech"}},
	{"绿盟", []string{"nsfocus"}},
	{"网御", []string{"leadsec"}},
	{"网神", []string{"legendsec", "qianxin"}},
	{"奇安信", []string{"qianxin", "qax"}},
	{"安恒", []string{"dbappsecurity", "dbapp"}},
	{"山石", []string{"hillstone"}},
	{"迪普", []string{"dptech"}},
	{"锐捷", []string{"ruijie"}},
	{"网康", []string{"netentsec"}},
	{"东软", []string{"neusoft", "neteye"}},
	{"梭子鱼", []string{"barracuda"}},
	{"齐治", []string{"shterm"}},
	{"华为", []string{"huawei"}},
	{"华三", []string{"h3c"}},
	{"中兴", []string{"zte"}},
	{"腾达", []string{"tenda"}},
	{"普联", []string{"tplink"}},
	{"迈普", []string{"maipu"}},
	{"烽火", []string{"fiberhome"}},
	{"海康", []string{"hikvision"}},
	{"大华", []string{"dahua"}},
	{"宇视", []string{"uniview"}},
	{"宝塔", []string{"baota", "bt"}},
	{"禅道", []string{"zentao"}},
	{"帝国cms", []string{"empirecms"}},
	{"织梦", []string{"dedecms"}},
	{"苹果cms", []string{"maccms"}},
	{"海洋cms", []string{"seacms"}},
	{"易优", []string{"eyoucms"}},
	{"骑士", []string{"74cms"}},
	{"迅睿", []string{"xunruicms"}},
	{"齐博", []string{"qibosoft"}},
	{"米拓", []string{"metinfo"}},
	{"科汛", []string{"kesion"}},
	{"云优", []string{"yunucms"}},
	{"五指", []string{"wuzhicms"}},
	{"易思", []string{"espcms"}},
	{"若依", []string{"ruoyi"}},
	{"铭飞", []string{"mcms"}},
}

// TemplateMeta is the subset of a POC template needed for fingerprint matching.
type TemplateMeta struct {
	ID         int64
	TemplateID string
	Name       string
	Tags       []string
}

// MatchTemplates returns template row IDs whose tags, id or name match one of
// the detected technologies. Tags are the primary signal; id/name tokens let
// hand-written templates participate without tags.
func MatchTemplates(techs []string, metas []TemplateMeta) []int64 {
	aliases := map[string]bool{}
	for _, tech := range techs {
		for _, a := range TechnologyAliases(tech) {
			if a = normToken(a); a != "" {
				aliases[a] = true
			}
		}
	}
	if len(aliases) == 0 {
		return nil
	}
	ids := []int64{}
	for _, m := range metas {
		matched := false
		for _, tag := range m.Tags {
			if aliases[normToken(tag)] {
				matched = true
				break
			}
		}
		if !matched {
			tokens := tokenize(m.TemplateID + " " + m.Name)
			for t := range tokens {
				if aliases[t] {
					matched = true
					break
				}
			}
		}
		if matched {
			ids = append(ids, m.ID)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func normToken(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func tokenize(s string) map[string]bool {
	out := map[string]bool{}
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			out[b.String()] = true
			b.Reset()
		}
	}
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return out
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
