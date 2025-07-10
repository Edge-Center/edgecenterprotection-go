package edgecenterprotection_go

import (
	"context"
	"fmt"
	"net/http"
)

const (
	// resourcesBasePathV2 base path for all resources requests
	// additional path is used for specific requests
	originsPathV2 = "origins"
)

// OriginsService is an interface for creating and managing origins for DDoS resources with the Edgecenter protection API.
// See: https://apidocs.edgecenter.ru/protection#tag/origins
type OriginsService interface {
	List(context.Context, int64, *OriginListOptions) ([]Origin, *Response, error)
	Get(context.Context, int64, int64) (*Origin, *Response, error)
	Create(context.Context, int64, *OriginCreateRequest) (*Origin, *Response, error)
	Delete(context.Context, int64, int64) (*Response, error)
	Update(context.Context, int64, int64, *OriginCreateRequest) (*Origin, *Response, error)
}

// OriginsServiceOp handles communication with methods of origins for DDoS resources of the Edgecenter protection API.
type OriginsServiceOp struct {
	client *Client
}

var _ OriginsService = &OriginsServiceOp{}

// Origin represents an origin for Edgecenter DDoS protection resource
type Origin struct {
	ID          int64  `json:"id"`
	IP          string `json:"origin_data"`
	Mode        string `json:"origin_mode"`
	Weight      int32  `json:"origin_weight"`
	MaxFails    int32  `json:"origin_max_fails"`
	FailTimeout int32  `json:"origin_fail_timeout"`
	Comment     string `json:"origin_comment"`
}

// OriginCreateRequest represents a request to create an origin for DDoS protection resource
type OriginCreateRequest struct {
	IP          string `json:"origin_data"`
	Mode        string `json:"origin_mode,omitempty"`
	Weight      uint32 `json:"origin_weight,omitempty"`
	MaxFails    uint32 `json:"origin_max_fails,omitempty"`
	FailTimeout uint32 `json:"origin_fail_timeout,omitempty"`
	Comment     string `json:"origin_comment,omitempty"`
}

// OriginListOptions specifies the optional query parameters to List method
type OriginListOptions struct {
	Limit  uint32 `url:"limit,omitempty" validate:"omitempty"`
	Offset uint32 `url:"offset,omitempty" validate:"omitempty"`
}

// List origins for single DDoS resource
func (s *OriginsServiceOp) List(ctx context.Context, resourceID int64, opts *OriginListOptions) ([]Origin, *Response, error) {
	path := fmt.Sprintf("%s/%d/%s", resourcesBasePathV2, resourceID, originsPathV2)

	path, err := addOptions(path, opts)
	if err != nil {
		return nil, nil, err
	}

	req, err := s.client.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, nil, err
	}

	root := new([]Origin)
	resp, err := s.client.Do(ctx, req, root)
	if err != nil {
		return nil, resp, err
	}

	return *root, resp, err
}

// Get single origin for DDoS resource
func (s *OriginsServiceOp) Get(ctx context.Context, resourceID int64, originID int64) (*Origin, *Response, error) {
	path := fmt.Sprintf("%s/%d/%s/%d", resourcesBasePathV2, resourceID, originsPathV2, originID)

	req, err := s.client.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, nil, err
	}

	origin := new(Origin)
	resp, err := s.client.Do(ctx, req, origin)
	if err != nil {
		return nil, resp, err
	}

	return origin, resp, err
}

// Add origin for DDoS resource
func (s *OriginsServiceOp) Create(ctx context.Context, resourceID int64, reqBody *OriginCreateRequest) (*Origin, *Response, error) {
	path := fmt.Sprintf("%s/%d/%s", resourcesBasePathV2, resourceID, originsPathV2)

	if reqBody == nil {
		return nil, nil, NewArgError("reqBody", "cannot be nil")
	}

	req, err := s.client.NewRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, nil, err
	}

	origin := new(Origin)
	resp, err := s.client.Do(ctx, req, origin)
	if err != nil {
		return nil, resp, err
	}

	return origin, resp, err
}

// Delete origin from DDoS resource
func (s *OriginsServiceOp) Delete(ctx context.Context, resourceID int64, originID int64) (*Response, error) {
	path := fmt.Sprintf("%s/%d/%s/%d", resourcesBasePathV2, resourceID, originsPathV2, originID)

	req, err := s.client.NewRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(ctx, req, nil)
	return resp, err
}

// Update origin for DDoS resource
func (s *OriginsServiceOp) Update(ctx context.Context, resourceID int64, originID int64, reqBody *OriginCreateRequest) (*Origin, *Response, error) {
	if reqBody == nil {
		return nil, nil, NewArgError("reqBody", "cannot be nil")
	}

	path := fmt.Sprintf("%s/%d/%s/%d", resourcesBasePathV2, resourceID, originsPathV2, originID)

	req, err := s.client.NewRequest(ctx, http.MethodPatch, path, reqBody)
	if err != nil {
		return nil, nil, err
	}

	origin := new(Origin)
	resp, err := s.client.Do(ctx, req, origin)
	if err != nil {
		return nil, resp, err
	}

	return origin, resp, err
}
