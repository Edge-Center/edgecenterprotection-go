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

	"github.com/hashicorp/go-retryablehttp"
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
	BaseURL    *url.URL

	// APIKey token for client
	APIKey string

	// Optional extra HTTP headers to set on every request to the API.
	headers map[string]string

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

// NewClient returns a new Edgecenter protection API, using the given
// http.Client to perform all requests.
func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	baseURL, _ := url.Parse(defaultBaseURL)

	c := &Client{HTTPClient: httpClient, BaseURL: baseURL}

	c.headers = make(map[string]string)

	return c
}

// ClientOpt are options for New.
type ClientOpt func(*Client) error

// NewWithRetries returns a new EdgecenterCloud API client with default retries config.
func NewWithRetries(httpClient *http.Client, opts ...ClientOpt) (*Client, error) {
	opts = append(opts, WithRetryAndBackoffs(
		RetryConfig{
			RetryMax:     defaultRetryMax,
			RetryWaitMin: PtrTo(float64(defaultRetryWaitMin)),
			RetryWaitMax: PtrTo(float64(defaultRetryWaitMax)),
		},
	))

	return New(httpClient, opts...)
}

// New returns a new EdgecenterCloud API client instance.
func New(httpClient *http.Client, opts ...ClientOpt) (*Client, error) {
	c := NewClient(httpClient)
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}

	// if retryMax is set it will use the retryablehttp client.
	if c.RetryConfig.RetryMax > 0 {
		retryableClient := retryablehttp.NewClient()
		retryableClient.RetryMax = c.RetryConfig.RetryMax

		if c.RetryConfig.RetryWaitMin != nil {
			retryableClient.RetryWaitMin = time.Duration(*c.RetryConfig.RetryWaitMin * float64(time.Second))
		}
		if c.RetryConfig.RetryWaitMax != nil {
			retryableClient.RetryWaitMax = time.Duration(*c.RetryConfig.RetryWaitMax * float64(time.Second))
		}

		// By default, this is nil and does not log.
		retryableClient.Logger = c.RetryConfig.Logger

		// if timeout is set, it is maintained before overwriting client with StandardClient()
		retryableClient.HTTPClient.Timeout = c.HTTPClient.Timeout

		// This custom ErrorHandler is required to provide errors that are consistent
		// with a *edgecloud.ErrorResponse and a non-nil *edgecloud.Response while providing
		// insight into retries using an internal header.
		retryableClient.ErrorHandler = func(resp *http.Response, err error, numTries int) (*http.Response, error) {
			if resp != nil {
				resp.Header.Add(internalHeaderRetryAttempts, strconv.Itoa(numTries))

				return resp, err
			}

			return resp, err
		}

		c.HTTPClient = retryableClient.StandardClient()
	}

	return c, nil
}

// SetBaseURL is a client option for setting the base URL.
func SetBaseURL(bu string) ClientOpt {
	return func(c *Client) error {
		u, err := url.Parse(bu)
		if err != nil {
			return err
		}

		c.BaseURL = u

		return nil
	}
}

// SetAPIKey is a client option for setting the APIKey token.
func SetAPIKey(apiKey string) ClientOpt {
	return func(c *Client) error {
		tokenPartsCount := 2
		parts := strings.SplitN(apiKey, " ", tokenPartsCount)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "apikey" {
			apiKey = parts[1]
		}
		c.APIKey = apiKey
		c.headers["Authorization"] = fmt.Sprintf("APIKey %s", c.APIKey)

		return nil
	}
}

