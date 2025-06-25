package edgecenterprotection_go

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	defaultBaseURL = "https://api.edgecenter.ru/dns"
	tokenHeader    = "APIKey"
	defaultTimeOut = 10 * time.Second
)

// Client manages communication with Edgecenter Protection API
type Client struct {
	// HTTP client used to communicate with the Edgecenter Protection API
	HTTPClient *http.Client

	// User agent for client
	UserAgent  string

	// User agent for client
	BaseURL    *url.URL

	// APIKey token for client
	APIKey string

	// Optional retry values. Setting the RetryConfig.RetryMax value enables automatically retrying requests
	// that fail with 429 or 500-level response codes
	RetryConfig RetryConfig
}

// RetryConfig sets the values used for enabling retries and backoffs for
// requests that fail with 429 or 500-level response codes using the go-retryablehttp client.
// RetryConfig.RetryMax must be configured to enable this behavior. RetryConfig.RetryWaitMin and
// RetryConfig.RetryWaitMax are optional, with the default values being 1.0 and 30.0, respectively.
//
// Note: Opting to use the go-retryablehttp client will overwrite any custom HTTP client passed into New().
type RetryConfig struct {
	RetryMax     int
	RetryWaitMin *float64    // Minimum time to wait
	RetryWaitMax *float64    // Maximum time to wait
	Logger       interface{} // Customer logger instance. Must implement either go-retryablehttp.Logger or go-retryablehttp.LeveledLogger
}

