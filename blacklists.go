package edgecenterprotection_go

import (
	"context"
	"fmt"
	"net/http"
)

const (
	// resourcesBasePathV2 base path for all resources requests
	// additional path is used for specific requests
	blacklistsPathV2 = "blacklists"
)

// BlacklistsService is an interface for creating and managing blacklists for DDoS resources with the Edgecenter protection API.
// See: https://apidocs.edgecenter.ru/protection#tag/blacklists
type BlacklistsService interface {
	List(context.Context, int64, *BlacklistListOptions) ([]Blacklist, *Response, error)
	Get(context.Context, int64, int64) (*Blacklist, *Response, error)
	Create(context.Context, int64, *BlacklistCreateRequest) (*Blacklist, *Response, error)
	Delete(context.Context, int64, int64) (*Response, error)
	Update(context.Context, int64, int64, *BlacklistCreateRequest) (*Blacklist, *Response, error)
}

// BlacklistsServiceOp handles communication with methods of blacklists for DDoS resources of the Edgecenter protection API.
type BlacklistsServiceOp struct {
	client *Client
}

var _ BlacklistsService = &BlacklistsServiceOp{}

// Blacklist represents an blacklist for Edgecenter DDoS protection resource
type Blacklist struct {
	ID int64  `json:"id"`
	IP string `json:"blacklist_data"`
}

// BlacklistCreateRequest represents a request to create an blacklist for DDoS protection resource
type BlacklistCreateRequest struct {
	IP string `json:"blacklist_data"`
}

// BlacklistListOptions specifies the optional query parameters to List method
type BlacklistListOptions struct {
	Limit  uint32 `url:"limit,omitempty" validate:"omitempty"`
	Offset uint32 `url:"offset,omitempty" validate:"omitempty"`
}

// List blacklists for single DDoS resource
func (s *BlacklistsServiceOp) List(ctx context.Context, resourceID int64, opts *BlacklistListOptions) ([]Blacklist, *Response, error) {
	path := fmt.Sprintf("%s/%d/%s", resourcesBasePathV2, resourceID, blacklistsPathV2)

	path, err := addOptions(path, opts)
	if err != nil {
		return nil, nil, err
	}

	req, err := s.client.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, nil, err
	}

	root := new([]Blacklist)
	resp, err := s.client.Do(ctx, req, root)
	if err != nil {
		return nil, resp, err
	}

	return *root, resp, err
}

// Get single blacklist for DDoS resource
func (s *BlacklistsServiceOp) Get(ctx context.Context, resourceID int64, blacklistID int64) (*Blacklist, *Response, error) {
	path := fmt.Sprintf("%s/%d/%s/%d", resourcesBasePathV2, resourceID, blacklistsPathV2, blacklistID)

	req, err := s.client.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, nil, err
	}

	blacklist := new(Blacklist)
	resp, err := s.client.Do(ctx, req, blacklist)
	if err != nil {
		return nil, resp, err
	}

	return blacklist, resp, err
}

// Add blacklist for DDoS resource
func (s *BlacklistsServiceOp) Create(ctx context.Context, resourceID int64, reqBody *BlacklistCreateRequest) (*Blacklist, *Response, error) {
	path := fmt.Sprintf("%s/%d/%s", resourcesBasePathV2, resourceID, blacklistsPathV2)

	if reqBody == nil {
		return nil, nil, NewArgError("reqBody", "cannot be nil")
	}

	req, err := s.client.NewRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, nil, err
	}

	blacklist := new(Blacklist)
	resp, err := s.client.Do(ctx, req, blacklist)
	if err != nil {
		return nil, resp, err
	}

	return blacklist, resp, err
}

// Delete blacklist from DDoS resource
func (s *BlacklistsServiceOp) Delete(ctx context.Context, resourceID int64, blacklistID int64) (*Response, error) {
	path := fmt.Sprintf("%s/%d/%s/%d", resourcesBasePathV2, resourceID, blacklistsPathV2, blacklistID)

	req, err := s.client.NewRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(ctx, req, nil)
	return resp, err
}

// Update blacklist for DDoS resource
func (s *BlacklistsServiceOp) Update(ctx context.Context, resourceID int64, blacklistID int64, reqBody *BlacklistCreateRequest) (*Blacklist, *Response, error) {
	if reqBody == nil {
		return nil, nil, NewArgError("reqBody", "cannot be nil")
	}

	path := fmt.Sprintf("%s/%d/%s/%d", resourcesBasePathV2, resourceID, blacklistsPathV2, blacklistID)

	req, err := s.client.NewRequest(ctx, http.MethodPatch, path, reqBody)
	if err != nil {
		return nil, nil, err
	}

	blacklist := new(Blacklist)
	resp, err := s.client.Do(ctx, req, blacklist)
	if err != nil {
		return nil, resp, err
	}

	return blacklist, resp, err
}
