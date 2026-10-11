package utils_test

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"loki-analyzer/internal/utils"
)

func TestProductionHTTPClientRejectsRedirects(t *testing.T) {
	client := utils.NewHTTPClient(3 * time.Second)
	if client.Timeout != 3*time.Second || client.CheckRedirect == nil {
		t.Fatal("unsafe HTTP defaults")
	}
	if !errors.Is(client.CheckRedirect(&http.Request{}, nil), http.ErrUseLastResponse) {
		t.Fatal("redirect was allowed")
	}
	// A nil custom Transport keeps Go's default verified TLS transport.
	if client.Transport != nil {
		t.Fatal("unexpected TLS transport override")
	}
}
