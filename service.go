package edgecenterprotection_go

import (
	"context"
	"net/http"
)

const (
	webprotectionBasePathV1            = "/v1/web-protection/client-info"
	infrastructureprotectionBasePathV1 = "/v1/infrastructure-protection/client-info"
)

// ServicesService is an interface for getting information about web & infrastructure protection status
// See: https://apidocs.edgecenter.ru/protection#tag/Service
type ServicesService interface {
	GetWebProtectionService(context.Context) (*WebProtectionDetails, *Response, error)
	GetInfrastructureProtectionService(context.Context) (*InfrastructureProtectionDetails, *Response, error)
}

// ServicesServiceOp handles communication with Service methods of the Edgecenter Protection API.
type ServicesServiceOp struct {
	client *Client
}

var _ ServicesService = &ServicesServiceOp{}

// WebProtectionDetails represents status of web protection for current client
type WebProtectionDetails struct {
	DDoSType int32 `json:"ddos_type"`
	WAF      bool  `json:"is_waf_enabled"`
	AntiBot  bool  `json:"is_antibot_enabled"`
}

// InfrastructureProtectionDetails represents status of infrastructure protection for current client
type InfrastructureProtectionDetails struct {
	HaveBill  bool    `json:"have_bill"`
	ClientIds []int64 `json:"accessible_client_ids"`
}

// Get web protection status
func (s *ServicesServiceOp) GetWebProtectionService(ctx context.Context) (*WebProtectionDetails, *Response, error) {
	req, err := s.client.NewRequest(ctx, http.MethodGet, webprotectionBasePathV1, nil)
	if err != nil {
		return nil, nil, err
	}

	status := new(WebProtectionDetails)
	resp, err := s.client.Do(ctx, req, status)
	if err != nil {
		return nil, resp, err
	}

	return status, resp, err
}

// Get infrastructure protection status
func (s *ServicesServiceOp) GetInfrastructureProtectionService(ctx context.Context) (*InfrastructureProtectionDetails, *Response, error) {
	req, err := s.client.NewRequest(ctx, http.MethodGet, infrastructureprotectionBasePathV1, nil)
	if err != nil {
		return nil, nil, err
	}

	status := new(InfrastructureProtectionDetails)
	resp, err := s.client.Do(ctx, req, status)
	if err != nil {
		return nil, resp, err
	}

	return status, resp, err
}
