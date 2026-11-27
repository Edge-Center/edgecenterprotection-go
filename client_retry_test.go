package edgecenterprotection_go

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fast429RetryConfig keeps the tests quick; the production defaults are ~1.1s.
func fast429RetryConfig(retryMax int) RetryOnTooManyRequestsConfig {
	return RetryOnTooManyRequestsConfig{
		RetryMax:     retryMax,
		RetryWaitMin: PtrTo(0.001),
		RetryWaitMax: PtrTo(0.002),
	}
}

func doRetryTestRequest(t *testing.T, client *Client, ctx context.Context) (*Response, error) {
	t.Helper()

	req, err := client.NewRequest(ctx, http.MethodGet, "test", nil)
	if err != nil {
		t.Fatal(err)
	}

	return client.Do(ctx, req, nil)
}

func TestRetryOnTooManyRequestsDefaults(t *testing.T) {
	if defaultTooManyRequestsRetryMax != 5 ||
		defaultTooManyRequestsRetryWaitMin != 1.1 ||
		defaultTooManyRequestsRetryWaitMax != 1.6 {
		t.Fatalf("unexpected defaults: max=%d wait=[%v, %v]",
			defaultTooManyRequestsRetryMax,
			defaultTooManyRequestsRetryWaitMin,
			defaultTooManyRequestsRetryWaitMax)
	}

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"message":"limited"}`))

			return
		}

		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client, err := New(server.Client(), SetBaseURL(server.URL),
		WithRetryOnTooManyRequests(RetryOnTooManyRequestsConfig{}))
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	resp, err := doRetryTestRequest(t, client, context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if got := calls.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2", got)
	}
	if elapsed := time.Since(start); elapsed < time.Duration(defaultTooManyRequestsRetryWaitMin*float64(time.Second)) ||
		elapsed > 5*time.Second {
		t.Fatalf("elapsed = %v, want about 1.1-1.6s", elapsed)
	}
	if got := resp.Header.Get(internalHeaderRetryAttempts); got != "" {
		t.Fatalf("successful response has %s = %q", internalHeaderRetryAttempts, got)
	}
}

func TestRetryOnTooManyRequestsDoesNotRetryOtherStatuses(t *testing.T) {
	for _, status := range []int{
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"message":"nope"}`))
			}))
			defer server.Close()

			client, err := New(server.Client(), SetBaseURL(server.URL),
				WithRetryOnTooManyRequests(fast429RetryConfig(3)))
			if err != nil {
				t.Fatal(err)
			}

			_, err = doRetryTestRequest(t, client, context.Background())
			if err == nil {
				t.Fatal("expected an error")
			}

			var respErr *ResponseError
			if !errors.As(err, &respErr) || respErr.Response.StatusCode != status {
				t.Fatalf("got error %v, want ResponseError with status %d", err, status)
			}
			if respErr.Attempts != 0 {
				t.Fatalf("Attempts = %d, want 0 for a non-retried response", respErr.Attempts)
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("requests = %d, want 1", got)
			}
		})
	}
}

func TestRetryOnTooManyRequestsDoesNotRetryTransportErrors(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)

		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack connection: %v", err)

			return
		}
		_ = conn.Close()
	}))
	defer server.Close()

	client, err := New(server.Client(), SetBaseURL(server.URL),
		WithRetryOnTooManyRequests(fast429RetryConfig(3)))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := doRetryTestRequest(t, client, context.Background()); err == nil {
		t.Fatal("expected a transport error")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
}

func TestRetryOnTooManyRequestsReturnsLastError(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = fmt.Fprintf(w, `{"message":"attempt %d"}`, calls.Add(1))
	}))
	defer server.Close()

	client, err := New(server.Client(), SetBaseURL(server.URL),
		WithRetryOnTooManyRequests(fast429RetryConfig(2)))
	if err != nil {
		t.Fatal(err)
	}

	_, err = doRetryTestRequest(t, client, context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}

	var respErr *ResponseError
	if !errors.As(err, &respErr) {
		t.Fatalf("got error %T, want *ResponseError", err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("requests = %d, want RetryMax+1 = 3", got)
	}
	if respErr.Response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", respErr.Response.StatusCode)
	}
	if respErr.Message != "attempt 3" {
		t.Fatalf("message = %q, want the last response body", respErr.Message)
	}
	if respErr.Attempts != 3 {
		t.Fatalf("Attempts = %d, want 3", respErr.Attempts)
	}
	if !strings.Contains(err.Error(), "giving up after 3 attempt(s)") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTooManyRequestsBackoff(t *testing.T) {
	min := time.Duration(defaultTooManyRequestsRetryWaitMin * float64(time.Second))
	max := time.Duration(defaultTooManyRequestsRetryWaitMax * float64(time.Second))
	backoff := jitteredBackoff(min, max)

	seen := make(map[time.Duration]struct{}, 100)
	for i := 0; i < 100; i++ {
		// Retry-After must be ignored: the API does not send it and the
		// per-second counter makes a long header-based delay unnecessary.
		resp := &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Header:     http.Header{"Retry-After": []string{"100"}},
		}
		got := backoff(min, max, i, resp)
		if got < min || got >= max {
			t.Fatalf("wait = %v, want [%v, %v)", got, min, max)
		}
		seen[got] = struct{}{}
	}
	if len(seen) < 10 {
		t.Fatalf("only %d distinct waits, expected jitter", len(seen))
	}

	if got := jitteredBackoff(min, min)(min, min, 5, nil); got != min {
		t.Fatalf("wait with min == max = %v, want %v", got, min)
	}
}

func TestRetryOnTooManyRequestsPartialWaitConfig(t *testing.T) {
	for _, tt := range []struct {
		name string
		cfg  RetryOnTooManyRequestsConfig
		min  time.Duration
		max  time.Duration
	}{
		{
			name: "only lower bound",
			cfg:  RetryOnTooManyRequestsConfig{RetryWaitMin: PtrTo(0.1)},
			min:  100 * time.Millisecond,
			max:  600 * time.Millisecond,
		},
		{
			name: "only upper bound",
			cfg:  RetryOnTooManyRequestsConfig{RetryWaitMax: PtrTo(0.7)},
			min:  200 * time.Millisecond,
			max:  700 * time.Millisecond,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if calls.Add(1) == 1 {
					w.WriteHeader(http.StatusTooManyRequests)

					return
				}
				_, _ = w.Write([]byte(`{}`))
			}))
			defer server.Close()

			client, err := New(server.Client(), SetBaseURL(server.URL), WithRetryOnTooManyRequests(tt.cfg))
			if err != nil {
				t.Fatal(err)
			}

			start := time.Now()
			if _, err := doRetryTestRequest(t, client, context.Background()); err != nil {
				t.Fatal(err)
			}
			if elapsed := time.Since(start); elapsed < tt.min || elapsed > time.Second {
				t.Fatalf("elapsed = %v, want [%v, %v]", elapsed, tt.min, tt.max)
			}
		})
	}
}

func TestRetryOnTooManyRequestsInvalidConfig(t *testing.T) {
	for _, tt := range []struct {
		name string
		cfg  RetryOnTooManyRequestsConfig
		arg  string
	}{
		{"negative retry max", RetryOnTooManyRequestsConfig{RetryMax: -1}, "RetryMax"},
		{"max below min", RetryOnTooManyRequestsConfig{RetryWaitMin: PtrTo(2.0), RetryWaitMax: PtrTo(1.0)}, "RetryWaitMax"},
		{"negative derived min", RetryOnTooManyRequestsConfig{RetryWaitMax: PtrTo(0.1)}, "RetryWaitMin"},
		{"negative min", RetryOnTooManyRequestsConfig{RetryWaitMin: PtrTo(-0.1)}, "RetryWaitMin"},
		{"negative max", RetryOnTooManyRequestsConfig{RetryWaitMax: PtrTo(-0.1)}, "RetryWaitMax"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(nil, WithRetryOnTooManyRequests(tt.cfg))

			var argErr *ArgError
			if !errors.As(err, &argErr) {
				t.Fatalf("got error %v, want *ArgError", err)
			}
			if argErr.arg != tt.arg {
				t.Fatalf("invalid argument = %q, want %q", argErr.arg, tt.arg)
			}
		})
	}
}

func TestExistingRetryPolicyIsUnchanged(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if calls.Add(1) <= 2 {
					w.WriteHeader(status)
					_, _ = w.Write([]byte(`{"message":"broken"}`))

					return
				}
				_, _ = w.Write([]byte(`{}`))
			}))
			defer server.Close()

			client, err := New(server.Client(), SetBaseURL(server.URL), WithRetryAndBackoffs(RetryConfig{
				RetryMax:     2,
				RetryWaitMin: PtrTo(0.001),
				RetryWaitMax: PtrTo(0.002),
			}))
			if err != nil {
				t.Fatal(err)
			}

			if _, err := doRetryTestRequest(t, client, context.Background()); err != nil {
				t.Fatal(err)
			}
			if got := calls.Load(); got != 3 {
				t.Fatalf("requests = %d, want 3", got)
			}
		})
	}
}

func TestNoRetriesWithoutOptIn(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"message":"limited"}`))

			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client, err := New(server.Client(), SetBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := doRetryTestRequest(t, client, context.Background()); err == nil {
		t.Fatal("expected an error")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
}

func TestTooManyRequestsPolicyTakesPrecedence(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"broken"}`))
	}))
	defer server.Close()

	client, err := New(server.Client(), SetBaseURL(server.URL),
		WithRetryAndBackoffs(RetryConfig{RetryMax: 3, RetryWaitMin: PtrTo(0.001), RetryWaitMax: PtrTo(0.002)}),
		WithRetryOnTooManyRequests(fast429RetryConfig(3)))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := doRetryTestRequest(t, client, context.Background()); err == nil {
		t.Fatal("expected an error")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1 (5xx must not be retried)", got)
	}
}

func TestRetryOnTooManyRequestsParallel(t *testing.T) {
	const (
		requests       = 120
		perSecondLimit = 40
	)

	var (
		mu        sync.Mutex
		window    int64
		inWindow  int
		throttled atomic.Int32
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		now := time.Now().Unix()
		if now != window {
			window = now
			inWindow = 0
		}
		inWindow++
		allowed := inWindow <= perSecondLimit
		mu.Unlock()

		if !allowed {
			throttled.Add(1)
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"message":"rate limited"}`))

			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client, err := New(server.Client(), SetBaseURL(server.URL),
		WithRetryOnTooManyRequests(RetryOnTooManyRequestsConfig{}))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	errs := make(chan error, requests)
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			req, err := client.NewRequest(ctx, http.MethodGet, "test", nil)
			if err != nil {
				errs <- err

				return
			}
			if _, err := client.Do(ctx, req, nil); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("parallel request failed: %v", err)
	}
	if throttled.Load() == 0 {
		t.Fatal("the mock did not produce 429 responses")
	}
	t.Logf("%d parallel requests, %d throttled, all succeeded", requests, throttled.Load())
}
