package edgecenterprotection_go

import (
	"context"
	"fmt"
	"net/http"
)

const (
	// base path for all resources requests
	resourcesBasePathV2 = "/v2/resources"

	// additional path
	resourcesDnsCheck = "dns-check"
)

// ResourcesService is an interface for creating and managing DDoS resources with the Edgecenter protection API.
// See: https://apidocs.edgecenter.ru/protection#tag/resources
type ResourcesService interface {
	List(context.Context, *ResourceListOptions) ([]Resource, *Response, error)
	Get(context.Context, int64) (*Resource, *Response, error)
	Create(context.Context, *ResourceCreateRequest) (*Resource, *Response, error)
	Delete(context.Context, int64) (*Response, error)
	Update(context.Context, int64, *ResourceCreateRequest) (*Resource, *Response, error)
	GetDomainName(context.Context, int64) (*DnsCheck, *Response, error)
	ValidateResourceRequest(ResourceCreateRequest) error
}

// ResourcesServiceOp handles communication with DDoS resources methods of the Edgecenter protection API.
type ResourcesServiceOp struct {
	client *Client
}

var _ ResourcesService = &ResourcesServiceOp{}

// Resource represents an Edgecenter DDoS protection resource
type Resource struct {
	ID              int64    `json:"id"`
	CreatedAt       string   `json:"created"`
	UpdatedAt       string   `json:"updated"`
	Name            string   `json:"name"`
	ClientID        int64    `json:"client"`
	Active          bool     `json:"active"`
	Enabled         bool     `json:"enabled"`
	WAF             bool     `json:"is_waf_enabled"`
	RedirectToHTTPS bool     `json:"is_redirect_to_https_enabled"`
	Status          string   `json:"status"`
	ServiceIP       string   `json:"service_ip,omitempty"`
	HTTPS2HTTP      byte     `json:"service_https2http,omitempty"`
	IPHash          byte     `json:"service_iphash,omitempty"`
	GeoIPMode       byte     `json:"service_geoip_mode,omitempty"`
	GeoIPList       string   `json:"service_geoip_list"`
	WWWRedir        byte     `json:"service_wwwredir"`
	MultipleOrigins bool     `json:"feature_multiple_origins"`
	WidlcardAliases bool     `json:"feature_wildcard_aliases"`
	SSLType         string   `json:"ssl_type,omitempty"`
	SSLExpire       uint64   `json:"service_ssl_expire,omitempty"`
	SSLStatus       string   `json:"service_ssl_status,omitempty"`
	TLSEnabled      []string `json:"tls_enabled,omitempty"`
	WaitForLE       uint64   `json:"wait_for_le,omitempty"`
}

// ResourceCreateRequest represents a request to create a Loadbalancer
type ResourceCreateRequest struct {
	Name            string   `json:"name"`
	Active          bool     `json:"active,omitempty"`
	MultipleOrigins bool     `json:"feature_multiple_origins,omitempty"`
	WidlcardAliases bool     `json:"feature_wildcard_aliases,omitempty"`
	RedirectToHTTPS bool     `json:"is_redirect_to_https_enabled,omitempty"`
	HTTPS2HTTP      byte     `json:"service_https2http,omitempty"`
	IPHash          byte     `json:"service_iphash,omitempty"`
	GeoIPMode       byte     `json:"service_geoip_mode,omitempty"`
	GeoIPList       string   `json:"service_geoip_list,omitempty"`
	WWWRedir        byte     `json:"service_wwwredir,omitempty"`
	TLSEnabled      []string `json:"tls_enabled"`
	SSLType         string   `json:"ssl_type,omitempty"`
	SSLCert         string   `json:"ssl_type,omitempty"`
	SSLKey          string   `json:"ssl_type,omitempty"`
	WAF             bool     `json:"is_waf_enabled,omitempty"`
}

// ResourceListOptions specifies the optional query parameters to List method
type ResourceListOptions struct {
	Limit           uint32 `url:"limit,omitempty" validate:"omitempty"`
	Offset          uint32 `url:"offset,omitempty" validate:"omitempty"`
	Ordering        string `url:"ordering,omitempty" validate:"omitempty"`
	ClientID        int64  `url"client,omitempty" validate:"omitempty"`
	Name            string `url:"name,omitempty" validate:"omitempty"`
	Active          bool   `url:"active,omitempty" validate:"omitempty"`
	MultipleOrigin  bool   `url:"feature_multiple_origins,omitempty" validate:"omitempty"`
	WildcardAliases bool   `url:"feature_wildcard_aliases,omitempty" validate:"omitempty"`
	ServiceIP       string `url:"service_ip,omitempty" validate:"omitempty"`
	OriginIP        string `url:"origin_ip,omitempty" validate:"omitempty"`
	Status          string `url:"status,omitempty" validate:"omitempty"`
	CreatedGt       string `url:"created_gte,omitempty" validate:"omitempty"`
	CleatedLt       string `url:"created_lte,omitempty" validate:"omitempty"`
	UpdatedGt       string `url:"updated_gte,omitempty" validate:"omitempty"`
	UpdatedLt       string `url:"updated_lte,omitempty" validate:"omitempty"`
}

// DnsCheck represents DNS data obtained from Edgecenter protection API for single resource
type DnsCheck struct {
	A         []string `json:"A"`
	InNetwork bool     `json:"is_in_network"`
}

// resourcesRoot represents list of DDoS resources as returned by list API
type resourcesRoot struct {
	Count     int        `json:"count"`
	Resources []Resource `json:"results"`
}

// List get DDoS resources
func (s *ResourcesServiceOp) List(ctx context.Context, opts *ResourceListOptions) ([]Resource, *Response, error) {
	path, err := addOptions(resourcesBasePathV2, opts)
	if err != nil {
		return nil, nil, err
	}

	req, err := s.client.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, nil, err
	}

	root := new(resourcesRoot)
	resp, err := s.client.Do(ctx, req, root)
	if err != nil {
		return nil, resp, err
	}

	return root.Resources, resp, err
}

// Get individual DDoS resource
func (s *ResourcesServiceOp) Get(ctx context.Context, resourceID int64) (*Resource, *Response, error) {
	path := fmt.Sprintf("%s/%d", resourcesBasePathV2, resourceID)

	req, err := s.client.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, nil, err
	}

	resource := new(Resource)
	resp, err := s.client.Do(ctx, req, resource)
	if err != nil {
		return nil, resp, err
	}

	return resource, resp, err
}

// Create new DDoS protection resource
func (s *ResourcesServiceOp) Create(ctx context.Context, reqBody *ResourceCreateRequest) (*Resource, *Response, error) {
	if reqBody == nil {
		return nil, nil, NewArgError("reqBody", "cannot be nil")
	}

	if s.ValidateResourceRequest(*reqBody) != nil {
		return nil, nil, NewArgError("reqBody", "failed validation")
	}

	req, err := s.client.NewRequest(ctx, http.MethodPost, resourcesBasePathV2, reqBody)
	if err != nil {
		return nil, nil, err
	}

	resource := new(Resource)
	resp, err := s.client.Do(ctx, req, resource)
	if err != nil {
		return nil, resp, err
	}

	return resource, resp, err
}

// Delete DdoS protection resource
func (s *ResourcesServiceOp) Delete(ctx context.Context, resourceID int64) (*Response, error) {
	path := fmt.Sprintf("%s/%d", resourcesBasePathV2, resourceID)

	req, err := s.client.NewRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(ctx, req, nil)
	return resp, err
}

// Update DDoS protection resource
func (s *ResourcesServiceOp) Update(ctx context.Context, resourceID int64, reqBody *ResourceCreateRequest) (*Resource, *Response, error) {
	if reqBody == nil {
		return nil, nil, NewArgError("reqBody", "cannot be nil")
	}

	if s.ValidateResourceRequest(*reqBody) != nil {
		return nil, nil, NewArgError("reqBody", "failed validation")
	}

	path := fmt.Sprintf("%s/%d", resourcesBasePathV2, resourceID)

	req, err := s.client.NewRequest(ctx, http.MethodPatch, path, reqBody)
	if err != nil {
		return nil, nil, err
	}

	resource := new(Resource)
	resp, err := s.client.Do(ctx, req, resource)
	if err != nil {
		return nil, resp, err
	}

	return resource, resp, err
}

// Get list of domain's IP addresses for DDoS resource
func (s *ResourcesServiceOp) GetDomainName(ctx context.Context, resourceID int64) (*DnsCheck, *Response, error) {
	path := fmt.Sprintf("%s/%d/%s", resourcesBasePathV2, resourceID, resourcesDnsCheck)

	req, err := s.client.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, nil, err
	}

	dnsAnswer := new(DnsCheck)
	resp, err := s.client.Do(ctx, req, dnsAnswer)
	if err != nil {
		return nil, resp, err
	}

	return dnsAnswer, resp, err
}

// Check request data matches restrictions
func (s *ResourcesServiceOp) ValidateResourceRequest(r ResourceCreateRequest) error {
	if r.HTTPS2HTTP != 0 && r.HTTPS2HTTP != 1 {
		return NewArgError("HTTPS2HTTP", "must be 0 or 1")
	}

	if r.IPHash != 0 && r.IPHash != 1 {
		return NewArgError("IPHash", "must be 0 or 1")
	}

	if r.GeoIPMode != 0 && r.GeoIPMode != 1 && r.GeoIPMode != 2 {
		return NewArgError("GeoIPMode", "must be 0, 1 or 2")
	}

	for _, tls := range r.TLSEnabled {
		if tls != "1" && tls != "1.1" && tls != "1.2" && tls != "1.3" {
			return NewArgError("TLSEnabled", "must be 1, 1.2, 1.2 or 1.3")
		}
	}

	return nil
}
