package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResponseHTTPMetadataAndCanonicalBytes(t *testing.T) {
	cases := []struct {
		name           string
		status         int
		types          []string
		encoding, body string
		accepted       bool
	}{
		{"canonical success", 200, []string{"application/json"}, "", `{"a":1,"b":2}`, true},
		{"changed success status", 201, []string{"application/json"}, "", `{"a":1,"b":2}`, false},
		{"changed content type", 200, []string{"text/plain"}, "", `{"a":1,"b":2}`, false},
		{"duplicate content type", 200, []string{"application/json", "text/plain"}, "", `{"a":1,"b":2}`, false},
		{"content transformation", 200, []string{"application/json"}, "gzip", `{"a":1,"b":2}`, false},
		{"noncanonical body", 200, []string{"application/json"}, "", `{"b":2,"a":1}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for _, v := range tc.types {
					w.Header().Add("Content-Type", v)
				}
				if tc.encoding != "" {
					w.Header().Set("Content-Encoding", tc.encoding)
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			client := srv.Client()
			client.Transport.(*http.Transport).DisableCompression = true
			_, err := exchange(client, "GET", srv.URL, nil, nil)
			if (err == nil) != tc.accepted {
				t.Fatalf("accepted=%v error=%v", tc.accepted, err)
			}
		})
	}
}
