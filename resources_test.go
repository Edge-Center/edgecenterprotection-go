package edgecenterprotection_go

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResourcesUpdateSSLType(t *testing.T) {
	custom := "custom"

	tests := []struct {
		name string
		req  ResourceUpdateRequest
		want string
	}{
		{name: "unset type is sent as null", req: ResourceUpdateRequest{}, want: "null"},
		{name: "set type is sent as is", req: ResourceUpdateRequest{SSLType: &custom}, want: `"custom"`},
		{name: "omitted type is left out", req: ResourceUpdateRequest{OmitSSLType: true}},
		{name: "omitted type is left out even when set", req: ResourceUpdateRequest{SSLType: &custom, OmitSSLType: true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var method, path string
			var body []byte

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				method, path = r.Method, r.URL.Path
				body, _ = io.ReadAll(r.Body)
				_, _ = w.Write([]byte("{}"))
			}))
			defer server.Close()

			client, err := New(server.Client(), SetBaseURL(server.URL))
			if err != nil {
				t.Fatal(err)
			}

			tt.req.TLSEnabled = []string{"1.2"}
			if _, _, err := client.Resources.Update(context.Background(), 42, &tt.req); err != nil {
				t.Fatal(err)
			}

			if method != http.MethodPatch || path != "/v2/resources/42" {
				t.Fatalf("got %s %s", method, path)
			}

			var fields map[string]json.RawMessage
			if err := json.Unmarshal(body, &fields); err != nil {
				t.Fatalf("body %s: %v", body, err)
			}

			got, sent := fields["ssl_type"]
			if sent != (tt.want != "") || string(got) != tt.want {
				t.Fatalf("ssl_type in %s, want %q", body, tt.want)
			}

			delete(fields, "ssl_type")
			if len(fields) != 11 || string(fields["tls_enabled"]) != `["1.2"]` {
				t.Fatalf("unexpected fields in %s", body)
			}
		})
	}
}
