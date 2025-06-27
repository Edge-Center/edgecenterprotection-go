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
	ID            int64
	Name          string
	ControlPanel  string
	created       string
	updated       string
	Waf           bool
	RedirectHTTPS bool
	ServiceIP     string
	BotProtection string
	SSL           ResourceSSLType
	SSLStatus     ResourceSSLStatus
	GeoIPMode     string
	GeoIPList     string
	Https2Http    bool
	WWWRedir      bool
	status        ResourceStatus
	enabled       bool
	active        bool
}
