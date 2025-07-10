package edgecenterprotection_go

import (
	"context"
	"fmt"
	"net/http"
)

const (
	// resourcesBasePathV2 base path for all resources requests
	// additional path is used for specific requests
	whitelistsPathV2 = "whitelists"
)

// WhitelistsService is an interface for creating and managing whitelists for DDoS resources with the Edgecenter protection API.
// See: https://apidocs.edgecenter.ru/protection#tag/whitelists
type WhitelistsService interface {
	List(context.Context, int64, *WhitelistListOptions) ([]Whitelist, *Response, error)
	Get(context.Context, int64, int64) (*Whitelist, *Response, error)
	Create(context.Context, int64, *WhitelistCreateRequest) (*Whitelist, *Response, error)
	Delete(context.Context, int64, int64) (*Response, error)
	Update(context.Context, int64, int64, *WhitelistCreateRequest) (*Whitelist, *Response, error)
}

// WhitelistsServiceOp handles communication with methods of whitelists for DDoS resources of the Edgecenter protection API.
type WhitelistsServiceOp struct {
	client *Client
}

var _ WhitelistsService = &WhitelistsServiceOp{}

// Whitelist represents an whitelist for Edgecenter DDoS protection resource
type Whitelist struct {
	ID int64  `json:"id"`
	IP string `json:"whitelist_data"`
}

// WhitelistCreateRequest represents a request to create an whitelist for DDoS protection resource
type WhitelistCreateRequest struct {
	IP string `json:"whitelist_data"`
}

// WhitelistListOptions specifies the optional query parameters to List method
type WhitelistListOptions struct {
	Limit  int `url:"limit,omitempty" validate:"omitempty"`
	Offset int `url:"offset,omitempty" validate:"omitempty"`
}

// List whitelists for single DDoS resource
func (s *WhitelistsServiceOp) List(ctx context.Context, resourceID int64, opts *WhitelistListOptions) ([]Whitelist, *Response, error) {
	path := fmt.Sprintf("%s/%d/%s", resourcesBasePathV2, resourceID, whitelistsPathV2)

	path, err := addOptions(path, opts)
	if err != nil {
		return nil, nil, err
	}

	req, err := s.client.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, nil, err
	}

	root := new([]Whitelist)
	resp, err := s.client.Do(ctx, req, root)
	if err != nil {
		return nil, resp, err
	}

	return *root, resp, err
}

// Get single whitelist for DDoS resource
func (s *WhitelistsServiceOp) Get(ctx context.Context, resourceID int64, whitelistID int64) (*Whitelist, *Response, error) {
	path := fmt.Sprintf("%s/%d/%s/%d", resourcesBasePathV2, resourceID, whitelistsPathV2, whitelistID)

	req, err := s.client.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, nil, err
	}

	whitelist := new(Whitelist)
	resp, err := s.client.Do(ctx, req, whitelist)
	if err != nil {
		return nil, resp, err
	}

	return whitelist, resp, err
}

// Add whitelist for DDoS resource
func (s *WhitelistsServiceOp) Create(ctx context.Context, resourceID int64, reqBody *WhitelistCreateRequest) (*Whitelist, *Response, error) {
	path := fmt.Sprintf("%s/%d/%s", resourcesBasePathV2, resourceID, whitelistsPathV2)

	if reqBody == nil {
		return nil, nil, NewArgError("reqBody", "cannot be nil")
	}

	req, err := s.client.NewRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, nil, err
	}

	whitelist := new(Whitelist)
	resp, err := s.client.Do(ctx, req, whitelist)
	if err != nil {
		return nil, resp, err
	}

	return whitelist, resp, err
}

// Delete whitelist from DDoS resource
func (s *WhitelistsServiceOp) Delete(ctx context.Context, resourceID int64, whitelistID int64) (*Response, error) {
	path := fmt.Sprintf("%s/%d/%s/%d", resourcesBasePathV2, resourceID, whitelistsPathV2, whitelistID)

	req, err := s.client.NewRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(ctx, req, nil)
	return resp, err
}

// Update whitelist for DDoS resource
func (s *WhitelistsServiceOp) Update(ctx context.Context, resourceID int64, whitelistID int64, reqBody *WhitelistCreateRequest) (*Whitelist, *Response, error) {
	if reqBody == nil {
		return nil, nil, NewArgError("reqBody", "cannot be nil")
	}

	path := fmt.Sprintf("%s/%d/%s/%d", resourcesBasePathV2, resourceID, whitelistsPathV2, whitelistID)

	req, err := s.client.NewRequest(ctx, http.MethodPatch, path, reqBody)
	if err != nil {
		return nil, nil, err
	}

	whitelist := new(Whitelist)
	resp, err := s.client.Do(ctx, req, whitelist)
	if err != nil {
		return nil, resp, err
	}

	return whitelist, resp, err
}
