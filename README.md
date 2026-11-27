# edgecenterprotection-go

## Retries on HTTP 429

Retries are opt-in. `WithRetryOnTooManyRequests` retries only `429 Too Many Requests`
with a random delay in `[1.1, 1.6)` seconds between attempts. `RetryMax` defaults to
5, i.e. 5 retries after the initial request (6 attempts in total). If only one wait
bound is set, the other shifts by the default 0.5s spread. Other 4xx, 5xx and
transport errors are returned immediately. `Retry-After` is ignored.

```go
client, err := edgecenterprotection_go.New(
    nil,
    edgecenterprotection_go.SetAPIKey(token),
    edgecenterprotection_go.WithRetryOnTooManyRequests(
        edgecenterprotection_go.RetryOnTooManyRequestsConfig{RetryMax: 5},
    ),
)
```

The existing `WithRetryAndBackoffs` policy (429 and 5xx with exponential backoff)
is unchanged. If both options are set, `WithRetryOnTooManyRequests` takes precedence.

## License

This project is licensed under the Mozilla Public License 2.0, see [LICENSE](LICENSE).
Copyright (c) 2025 LLC "EDGECENTER"
