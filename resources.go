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
	active        bool              `json:"active,omitempty"`
	Waf           bool              `json:"is_waf_enabled,omitempty"`
	RedirectHTTPS bool              `json:"is_redirect_to_https_enabled,omitempty"`
	BotProtection byte              `json:"service_botprotect,omitempty"`
	SSL           ResourceSSLType   `json:"ssl_type,omitempty"`
	SSLStatus     ResourceSSLStatus `json:"service_ssl_status,omitempty"`
	GeoIPMode     byte              `json:"service_geoip_mode,omitempty"`
	GeoIPList     string            `json:"service_geoip_list,omitempty"`
	Https2Http    byte              `json:"service_https2http,omitempty"`
	WWWRedir      byte              `json:"service_wwwredir,omitempty"`

	aliases      []ResourceAlias      `json:"aliases,omitempty"`
	origins      []ResourceOrigin     `json:"origins,omitempty"`
	whitelists   []ResourceWhitelist  `json:"whitelists,omitempty"`
	blacklists   []ResourceBlacklist  `json:"blacklists,omitempty"`
	http_headers []ResourceHTTPHeader `json:"http_headers,omitempty"`

	// read-only
	ID           int64          `json:"id,omitempty"`
	enabled      bool           `json:"enabled,omitempty"`
	DomainName   string         `json:"name,omitempty"`
	status       ResourceStatus `json:"status,omitempty"`
	ControlPanel int64          `json:"client,omitempty"`
	created      string         `json:"created,omitempty"`
	updated      string         `json:"updated,omitempty"`
	ServiceIP    string         `json:"service_ip,omitempty"`

	TLSVersionsEnabled []string `json:"tls_versions_enabled,omitempty"`

	// internal parameters
	ServiceCDN             int64  `json:"service_cdn,omitempty"`
	ServiceCDNHost         string `json:"service_cdn_host,omitempty"`
	ServiceCDNProxyHost    string `json:"service_cdn_proxy_host,omitempty"`
	ServiceEnable          int64  `json:"service_enable,omitempty"`
	ServiceForceSSL        int64  `json:"service_forcessl,omitempty"`
	ServiceGlobalWhitelist int64  `json:"service_global_whitelist,omitempty"`
	ServiceHTTP2           int64  `json:"service_http2,omitempty"`
	ServiceIPHash          int64  `json:"service_iphash,omitempty"`
	ServiceMethods         int64  `json:"service_methods,omitempty"`
	ServiceStream          int64  `json:"service_stream,omitempty"`
}

type ResourceAlias struct {
	Domain    string            `json:"alias_data,omitempty"`
	SSLExpire int64             `json:"alias_ssl_expire,omitempty"`
	SSL       ResourceSSLType   `json:"ssl_type,omitempty"`
	SSLStatus ResourceSSLStatus `json:"service_ssl_status,omitempty"`

	// read-only
	ID      int64  `json:"id,omitempty"`
	created string `json:"alias_created,omitempty"`
	updated string `json:"alias_updated,omitempty"`

	// internal
	AliasID int64 `json:"alias_id,omitempty"`
}

type ResourceOrigin struct {
	Data        string `json:"origin_data,omitempty"`
	Weight      byte   `json:"origin_weight,omitempty"`
	Mode        string `json:"origin_mode,omitempty"`
	FailTimeout int32  `json:"origin_fail_timeout,omitempty"`
	MaxFails    int32  `json:"origin_max_fails,omitempty"`

	// read-only
	ID int64 `json:"id,omitempty"`

	// internal
	OriginID int64 `json:"origin_id,omitempty"`
}

type ResourceWhitelist struct {
	Data string `json:"whitelist_data,omitempty"`

	// read-only
	ID int64 `json:"id,omitempty"`

	// internal
	WhitelistID int64 `json:"whitelist_id,omitempty"`
}

type ResourceBlacklist struct {
	Data string `json:"blacklist_data,omitempty"`

	// read-only
	ID int64 `json:"id,omitempty"`

	// internal
	BlacklistID int64 `json:"blacklist_id,omitempty"`
}

type ResourceHTTPHeader struct {
	key   string `json:"header_key,omitempty"`
	value string `json:"header_value,omitempty"`

	// read-only
	ID int64 `json:"id,omitempty"`
}
