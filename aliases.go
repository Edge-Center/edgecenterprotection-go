package edgecenterprotection_go

import (
	"context"
	"fmt"
	"net/http"
)

const (
	// resourcesBasePathV2 base path for all resources requests
	// additional path is used for specific requests
	aliasesPathV2 = "aliases"
)

// AliasesService is an interface for creating and managing aliases for DDoS resources with the Edgecenter protection API.
// See: https://apidocs.edgecenter.ru/protection#tag/aliases
type AliasesService interface {
	List(context.Context, int64, *AliasListOptions) ([]Alias, *Response, error)
	Get(context.Context, int64, int64) (*Alias, *Response, error)
	Create(context.Context, int64, *AliasCreateRequest) (*Alias, *Response, error)
	Delete(context.Context, int64, int64) (*Response, error)
	Update(context.Context, int64, int64, *AliasUpdateRequest) (*Alias, *Response, error)
	ValidateAliasCreateRequest(AliasCreateRequest) error
	ValidateAliasUpdateRequest(AliasUpdateRequest) error
}

// AliasesServiceOp handles communication with methods of aliases for DDoS resources of the Edgecenter protection API.
type AliasesServiceOp struct {
	client *Client
}

var _ AliasesService = &AliasesServiceOp{}

// Alias represents an alias for Edgecenter DDoS protection resource
type Alias struct {
	ID        int64   `json:"id"`
	Created   string  `json:"alias_created"`
	Updated   string  `json:"alias_updated"`
	Name      string  `json:"alias_data"`
	SSLExpire int     `json:"alias_ssl_expire,omitempty"`
	SSLStatus int     `json:"alias_ssl_status"`
	SSLType   *string `json:"alias_ssl_type"`
}

// AliasCreateRequest represents a request to create an alias for DDoS protection resource
type AliasCreateRequest struct {
	Name    string  `json:"alias_data"`
	SSLType *string `json:"alias_ssl_type"`
	SSLKey  *string `json:"alias_ssl_key,omitempty"`
	SSLCrt  *string `json:"alias_ssl_crt,omitempty"`
}

// AliasUpdateRequest represents a request to update an alias for DDoS protection resource
type AliasUpdateRequest struct {
	SSLType *string `json:"alias_ssl_type"`
	SSLKey  *string `json:"alias_ssl_key,omitempty"`
	SSLCrt  *string `json:"alias_ssl_crt,omitempty"`
}

// AliasListOptions specifies the optional query parameters to List method
type AliasListOptions struct {
	Limit  int `url:"limit,omitempty" validate:"omitempty"`
	Offset int `url:"offset,omitempty" validate:"omitempty"`
}

// List aliases for single DDoS resource
func (s *AliasesServiceOp) List(ctx context.Context, resourceID int64, opts *AliasListOptions) ([]Alias, *Response, error) {
	path := fmt.Sprintf("%s/%d/%s", resourcesBasePathV2, resourceID, aliasesPathV2)

	path, err := addOptions(path, opts)
	if err != nil {
		return nil, nil, err
	}

	req, err := s.client.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, nil, err
	}

	root := new([]Alias)
	resp, err := s.client.Do(ctx, req, root)
	if err != nil {
		return nil, resp, err
	}

	return *root, resp, err
}

// Get single alias for DDoS resource
func (s *AliasesServiceOp) Get(ctx context.Context, resourceID int64, aliasID int64) (*Alias, *Response, error) {
	path := fmt.Sprintf("%s/%d/%s/%d", resourcesBasePathV2, resourceID, aliasesPathV2, aliasID)

	req, err := s.client.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, nil, err
	}

	alias := new(Alias)
	resp, err := s.client.Do(ctx, req, alias)
	if err != nil {
		return nil, resp, err
	}

	return alias, resp, err
}

// Add alias for DDoS resource
func (s *AliasesServiceOp) Create(ctx context.Context, resourceID int64, reqBody *AliasCreateRequest) (*Alias, *Response, error) {
	path := fmt.Sprintf("%s/%d/%s", resourcesBasePathV2, resourceID, aliasesPathV2)

	if reqBody == nil {
		return nil, nil, NewArgError("reqBody", "cannot be nil")
	}

	err := s.ValidateAliasCreateRequest(*reqBody)
	if err != nil {
		return nil, nil, err
	}

	req, err := s.client.NewRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, nil, err
	}

	alias := new(Alias)
	resp, err := s.client.Do(ctx, req, alias)
	if err != nil {
		return nil, resp, err
	}

	return alias, resp, err
}

// Delete alias from DDoS resource
func (s *AliasesServiceOp) Delete(ctx context.Context, resourceID int64, aliasID int64) (*Response, error) {
	path := fmt.Sprintf("%s/%d/%s/%d", resourcesBasePathV2, resourceID, aliasesPathV2, aliasID)

	req, err := s.client.NewRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(ctx, req, nil)
	return resp, err
}

// Update alias for DDoS resource
func (s *AliasesServiceOp) Update(ctx context.Context, resourceID int64, aliasID int64, reqBody *AliasUpdateRequest) (*Alias, *Response, error) {
	if reqBody == nil {
		return nil, nil, NewArgError("reqBody", "cannot be nil")
	}

	err := s.ValidateAliasUpdateRequest(*reqBody)
	if err != nil {
		return nil, nil, err
	}

	path := fmt.Sprintf("%s/%d/%s/%d", resourcesBasePathV2, resourceID, aliasesPathV2, aliasID)

	req, err := s.client.NewRequest(ctx, http.MethodPatch, path, reqBody)
	if err != nil {
		return nil, nil, err
	}

	alias := new(Alias)
	resp, err := s.client.Do(ctx, req, alias)
	if err != nil {
		return nil, resp, err
	}

	return alias, resp, err
}

// Check create request data matches restrictions
func (s *AliasesServiceOp) ValidateAliasCreateRequest(r AliasCreateRequest) error {
	ssltype := r.SSLType
	if ssltype != nil {
		if *ssltype != "custom" && *ssltype != "le" {
			return NewArgError("SSLType", "must be custom or le")
		}
	}

	return nil
}

// Check update request data matches restrictions
func (s *AliasesServiceOp) ValidateAliasUpdateRequest(r AliasUpdateRequest) error {
	ssltype := r.SSLType
	if ssltype != nil {
		if *ssltype != "custom" && *ssltype != "le" {
			return NewArgError("SSLType", "must be custom or le")
		}
	}

	return nil
}
