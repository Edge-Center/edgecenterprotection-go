package edgecenterprotection_go

import (
	"context"
)

type ResourceService interface {
	Create(ctx context.Context, req *ProtectionResource) (*ProtectionResource, error)
	Get(ctx context.Context, id int64) (*ProtectionResource, error)
	Update(ctx context.Context, id int64, req *ProtectionResource) (*ProtectionResource, error)
	Delete(ctx context.Context, resourceID int64) error
	List(ctx context.Context, ordering string) ([]ProtectionResource, error)
}

type ResourceStatus string

const (
	ProcessesStatus ResourceStatus = "processed"
	ErrorStatus     ResourceStatus = "error"
	ActiveStatus    ResourceStatus = "active"
	Suspended       ResourceStatus = "suspended"
)

var ResourceBotProtection = map[bool]byte{
	false: 0,
	true:  4,
}

type ResourceSSLType string

const (
	CustomSSL ResourceSSLType = "custom"
	LESSL     ResourceSSLType = "le"
	NullSSL   ResourceSSLType = ""
)

type ResourceSSLStatus string

const (
	SSLRequested  ResourceSSLStatus = "requested"
	SSLProcessing ResourceSSLStatus = "processing"
	SSLErrorRetry ResourceSSLStatus = "error_retry"
	SSLError      ResourceSSLStatus = "error"
	SSLDone       ResourceSSLStatus = "done"
	SSLNull       ResourceSSLStatus = ""
)

var ResourceGeoIPMode = map[string]byte{
	"disabled":  0,
	"allowlist": 1,
	"denylist":  2,
}

var ResourceHTTPS2HTTP = map[bool]byte{
	false: 0,
	true:  1,
}

type ProtectionResource struct {
	active        bool              `json:"active"`
	Waf           bool              `json:"is_waf_enabled"`
	RedirectHTTPS bool              `json:"is_redirect_to_https_enabled"`
	BotProtection byte              `json:"service_botprotect"`
	SSL           ResourceSSLType   `json:"ssl_type"`
	SSLStatus     ResourceSSLStatus `json:"service_ssl_status"`
	GeoIPMode     byte              `json:"service_geoip_mode"`
	GeoIPList     string            `json:"service_geoip_list"`
	Https2Http    byte              `json:"service_https2http"`
	WWWRedir      byte              `json:"service_wwwredir"`

	aliases      []ResourceAlias      `json:"aliases"`
	origins      []ResourceOrigin     `json:"origins"`
	whitelists   []ResourceWhitelist  `json:"whitelists"`
	blacklists   []ResourceBlacklist  `json:"blacklists"`
	http_headers []ResourceHttpHeader `json:"http_headers"`

	// read-only
	ID           int64          `json:"id"`
	enabled      bool           `json:"enabled"`
	DomainName   string         `json:"name"`
	status       ResourceStatus `json:"status"`
	ControlPanel int64          `json:"client"`
	created      string         `json:"created"`
	updated      string         `json:"updated"`
	ServiceIP    string         `json:"service_ip"`

	TLSVersionsEnabled []string `json:"tls_versions_enabled"`

	// internal parameters
	ServiceCDN             int64  `json:"service_cdn"`
	ServiceCDNHost         string `json:"service_cdn_host"`
	ServiceCDNProxyHost    string `json:"service_cdn_proxy_host"`
	ServiceEnable          int64  `json:"service_enable"`
	ServiceForceSSL        int64  `json:"service_forcessl"`
	ServiceGlobalWhitelist int64  `json:"service_global_whitelist"`
	ServiceHTTP2           int64  `json:"service_http2"`
	ServiceIPHash          int64  `json:"service_iphash"`
	ServiceMethods         int64  `json:"service_methods"`
	ServiceStream          int64  `json:"service_stream"`
}

type ResourceAlias struct {
	Domain    string            `json:"alias_data"`
	SSLExpire int64             `json:"alias_ssl_expire"`
	SSL       ResourceSSLType   `json:"ssl_type"`
	SSLStatus ResourceSSLStatus `json:"service_ssl_status"`

	// read-only
	ID      int64  `json:"id"`
	created string `json:"alias_created"`
	updated string `json:"alias_updated"`

	// internal
	AliasID int64 `json:"alias_id"`
}

type ResourceOrigin struct {
	Data        string `json:"origin_data"`
	Weight      byte   `json:"origin_weight"`
	Mode        string `json:"origin_mode"`
	FailTimeout int32  `json:"origin_fail_timeout"`
	MaxFails    int32  `json:"origin_max_fails"`

	// read-only
	ID int64 `json:"id"`

	// internal
	OriginID int64 `json:"origin_id"`
}

type ResourceWhitelist struct {
	Data string `json:"whitelist_data"`

	// read-only
	ID int64 `json:"id"`

	// internal
	WhitelistID int64 `json:"whitelist_id"`
}

type ResourceBlacklist struct {
	Data string `json:"blacklist_data"`

	// read-only
	ID int64 `json:"id"`

	// internal
	BlacklistID int64 `json:"blacklist_id"`
}

type ResourceHTTPHeader struct {
	key   string `json:"header_key"`
	value string `json:"header_value"`

	// read-only
	ID int64 `json:"id"`
}
