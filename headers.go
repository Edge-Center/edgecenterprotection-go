package edgecenterprotection_go

import (
	"context"
	"fmt"
	"net/http"
)

const (
	// resourcesBasePathV2 base path for all resources requests
	// additional path is used for specific requests
	headersPathV2 = "headers"
)

// HeadersService is an interface for managing headers for DDoS resources with the Edgecenter protection API.
// See: https://apidocs.edgecenter.ru/protection#tag/headers
type HeadersService interface {
	List(context.Context, int64) ([]Header, *Response, error)
	Get(context.Context, int64, int64) (*Header, *Response, error)
	Create(context.Context, int64, *HeaderCreateRequest) (*Header, *Response, error)
	Delete(context.Context, int64, int64) (*Response, error)
	Update(context.Context, int64, int64, *HeaderCreateRequest) (*Header, *Response, error)
}

// HeadersServiceOp handles communication with methods of headers for DDoS resources of the Edgecenter protection API.
type HeadersServiceOp struct {
	client *Client
}

var _ HeadersService = &HeadersServiceOp{}

// Header represents an header for Edgecenter DDoS protection resource
type Header struct {
	ID    int64  `json:"id"`
	Key   string `json:"header_key"`
	Value string `json:"header_value"`
}

// HeaderCreateRequest represents a request to create an header for DDoS protection resource
type HeaderCreateRequest struct {
	Key   string `json:"header_key"`
	Value string `json:"header_value"`
}

// List headers for single DDoS resource
func (s *HeadersServiceOp) List(ctx context.Context, resourceID int64) ([]Header, *Response, error) {
	path := fmt.Sprintf("%s/%d/%s", resourcesBasePathV2, resourceID, headersPathV2)

	req, err := s.client.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, nil, err
	}

	root := new([]Header)
	resp, err := s.client.Do(ctx, req, root)
	if err != nil {
		return nil, resp, err
	}

	return *root, resp, err
}

// Get single header for DDoS resource
func (s *HeadersServiceOp) Get(ctx context.Context, resourceID int64, headerID int64) (*Header, *Response, error) {
	path := fmt.Sprintf("%s/%d/%s/%d", resourcesBasePathV2, resourceID, headersPathV2, headerID)

	req, err := s.client.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, nil, err
	}

	header := new(Header)
	resp, err := s.client.Do(ctx, req, header)
	if err != nil {
		return nil, resp, err
	}

	return header, resp, err
}

// Add header for DDoS resource
func (s *HeadersServiceOp) Create(ctx context.Context, resourceID int64, reqBody *HeaderCreateRequest) (*Header, *Response, error) {
	path := fmt.Sprintf("%s/%d/%s", resourcesBasePathV2, resourceID, headersPathV2)

	if reqBody == nil {
		return nil, nil, NewArgError("reqBody", "cannot be nil")
	}

	req, err := s.client.NewRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, nil, err
	}

	header := new(Header)
	resp, err := s.client.Do(ctx, req, header)
	if err != nil {
		return nil, resp, err
	}

	return header, resp, err
}

// Delete header from DDoS resource
func (s *HeadersServiceOp) Delete(ctx context.Context, resourceID int64, headerID int64) (*Response, error) {
	path := fmt.Sprintf("%s/%d/%s/%d", resourcesBasePathV2, resourceID, headersPathV2, headerID)

	req, err := s.client.NewRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(ctx, req, nil)
	return resp, err
}

// Update header for DDoS resource
func (s *HeadersServiceOp) Update(ctx context.Context, resourceID int64, headerID int64, reqBody *HeaderCreateRequest) (*Header, *Response, error) {
	if reqBody == nil {
		return nil, nil, NewArgError("reqBody", "cannot be nil")
	}

	path := fmt.Sprintf("%s/%d/%s/%d", resourcesBasePathV2, resourceID, headersPathV2, headerID)

	req, err := s.client.NewRequest(ctx, http.MethodPatch, path, reqBody)
	if err != nil {
		return nil, nil, err
	}

	header := new(Header)
	resp, err := s.client.Do(ctx, req, header)
	if err != nil {
		return nil, resp, err
	}

	return header, resp, err
}
