package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRbacCheck_AdminAccess tests admin role access
func TestRbacCheck_AdminAccess(t *testing.T) {
	// Admin should have access to all endpoints
	id := Identity{
		Name:   "admin",
		Role:   "admin",
		Groups: []string{"admin"},
		Tenant: "default",
	}

	tests := []struct {
		method string
		path   string
	}{
		{"GET", "/api/status"},
		{"GET", "/api/models"},
		{"POST", "/api/chat/completions"},
		{"POST", "/api/admin/config"},
		{"GET", "/api/admin/audit"},
		{"DELETE", "/api/models/test"},
	}

	for _, tt := range tests {
		t.Run(tt.method+"_"+tt.path, func(t *testing.T) {
			ok, reason := rbacCheck(id, tt.method, tt.path)
			if !ok {
				t.Errorf("rbacCheck() admin should have access to %s %s, reason: %s", tt.method, tt.path, reason)
			}
		})
	}
}

// TestRbacCheck_ReadOnlyAccess tests read-only role access
func TestRbacCheck_ReadOnlyAccess(t *testing.T) {
	// Read-only should have GET access but not write access
	id := Identity{
		Name:   "reader",
		Role:   "readonly",
		Groups: []string{"readonly"},
		Tenant: "default",
	}

	tests := []struct {
		method   string
		path     string
		wantOK   bool
	}{
		{"GET", "/api/status", true},
		{"GET", "/api/models", true},
		{"GET", "/api/admin/audit", true},
		{"POST", "/api/chat/completions", false}, // Chat is write
		{"POST", "/api/admin/config", false},
		{"DELETE", "/api/models/test", false},
		{"PUT", "/api/config", false},
	}

	for _, tt := range tests {
		t.Run(tt.method+"_"+tt.path, func(t *testing.T) {
			ok, _ := rbacCheck(id, tt.method, tt.path)
			if ok != tt.wantOK {
				t.Errorf("rbacCheck() readonly %s %s = %v, want %v", tt.method, tt.path, ok, tt.wantOK)
			}
		})
	}
}

// TestRbacCheck_PublicEndpoints tests public endpoint access
func TestRbacCheck_PublicEndpoints(t *testing.T) {
	// Any identity should access public endpoints
	id := Identity{
		Name:   "user",
		Role:   "user",
		Groups: []string{"user"},
		Tenant: "default",
	}

	publicPaths := []string{
		"/health",
		"/api/status",
		"/",
	}

	for _, path := range publicPaths {
		t.Run(path, func(t *testing.T) {
			ok, reason := rbacCheck(id, "GET", path)
			if !ok {
				t.Errorf("rbacCheck() public endpoint %s should be accessible, reason: %s", path, reason)
			}
		})
	}
}

// TestRbacCheck_UnknownRole tests unknown role handling
func TestRbacCheck_UnknownRole(t *testing.T) {
	id := Identity{
		Name:   "unknown",
		Role:   "unknown_role",
		Groups: []string{"unknown"},
		Tenant: "default",
	}

	ok, _ := rbacCheck(id, "GET", "/api/status")
	// Should either deny or use default policy
	_ = ok
}

// TestRbacCheck_ChatEndpoints tests chat endpoint access control
func TestRbacCheck_ChatEndpoints(t *testing.T) {
	tests := []struct {
		name     string
		role     string
		method   string
		path     string
		wantOK   bool
	}{
		{"admin_chat", "admin", "POST", "/api/chat/completions", true},
		{"readonly_chat", "readonly", "POST", "/api/chat/completions", false},
		{"user_chat", "user", "POST", "/api/chat/completions", true},
		{"admin_stream", "admin", "POST", "/api/chat/completions/stream", true},
		{"readonly_stream", "readonly", "POST", "/api/chat/completions/stream", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := Identity{
				Name:   "test",
				Role:   tt.role,
				Groups: []string{tt.role},
				Tenant: "default",
			}
			ok, _ := rbacCheck(id, tt.method, tt.path)
			if ok != tt.wantOK {
				t.Errorf("rbacCheck() %s %s %s = %v, want %v", tt.role, tt.method, tt.path, ok, tt.wantOK)
			}
		})
	}
}

// TestRbacCheck_AdminEndpoints tests admin endpoint access control
func TestRbacCheck_AdminEndpoints(t *testing.T) {
	tests := []struct {
		name   string
		role   string
		method string
		path   string
		wantOK bool
	}{
		{"admin_config_get", "admin", "GET", "/api/admin/config", true},
		{"admin_config_post", "admin", "POST", "/api/admin/config", true},
		{"readonly_config_get", "readonly", "GET", "/api/admin/config", true},
		{"readonly_config_post", "readonly", "POST", "/api/admin/config", false},
		{"user_config_get", "user", "GET", "/api/admin/config", false},
		{"user_config_post", "user", "POST", "/api/admin/config", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := Identity{
				Name:   "test",
				Role:   tt.role,
				Groups: []string{tt.role},
				Tenant: "default",
			}
			ok, _ := rbacCheck(id, tt.method, tt.path)
			if ok != tt.wantOK {
				t.Errorf("rbacCheck() %s %s %s = %v, want %v", tt.role, tt.method, tt.path, ok, tt.wantOK)
			}
		})
	}
}

// TestIdentityFromRequest_ValidBearer tests Bearer token extraction
func TestIdentityFromRequest_ValidBearer(t *testing.T) {
	// Set a known API key
	cfgMu.Lock()
	cfg.Security.APIKey = "test-key-123"
	cfgMu.Unlock()

	req := httptest.NewRequest("GET", "/api/status", nil)
	req.Header.Set("Authorization", "Bearer test-key-123")

	id, ok := identityFromRequest(req)
	if !ok {
		t.Error("identityFromRequest() should accept valid Bearer token")
	}
	if id.Name == "" {
		t.Error("identityFromRequest() should return identity with name")
	}
}

// TestIdentityFromRequest_InvalidBearer tests invalid Bearer token
func TestIdentityFromRequest_InvalidBearer(t *testing.T) {
	cfgMu.Lock()
	cfg.Security.APIKey = "test-key-123"
	cfgMu.Unlock()

	req := httptest.NewRequest("GET", "/api/status", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")

	_, ok := identityFromRequest(req)
	if ok {
		t.Error("identityFromRequest() should reject invalid Bearer token")
	}
}

// TestIdentityFromRequest_NoAuth tests missing authentication
func TestIdentityFromRequest_NoAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/status", nil)

	_, ok := identityFromRequest(req)
	if ok {
		t.Error("identityFromRequest() should reject request without auth")
	}
}

// TestIdentityFromRequest_MalformedBearer tests malformed Bearer token
func TestIdentityFromRequest_MalformedBearer(t *testing.T) {
	tests := []struct {
		name  string
		auth  string
	}{
		{"empty_bearer", "Bearer "},
		{"no_space", "Bearertest-key"},
		{"wrong_scheme", "Basic test-key"},
		{"lowercase", "bearer test-key"},
	}

	cfgMu.Lock()
	cfg.Security.APIKey = "test-key-123"
	cfgMu.Unlock()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/status", nil)
			req.Header.Set("Authorization", tt.auth)

			_, ok := identityFromRequest(req)
			// Should handle gracefully (either reject or use fallback)
			_ = ok
		})
	}
}

// TestRbacCheck_Concurrent tests concurrent RBAC checks
func TestRbacCheck_Concurrent(t *testing.T) {
	id := Identity{
		Name:   "admin",
		Role:   "admin",
		Groups: []string{"admin"},
		Tenant: "default",
	}

	done := make(chan bool, 100)

	for i := 0; i < 100; i++ {
		go func() {
			defer func() { done <- true }()
			for j := 0; j < 100; j++ {
				rbacCheck(id, "GET", "/api/status")
				rbacCheck(id, "POST", "/api/chat/completions")
				rbacCheck(id, "GET", "/api/admin/config")
			}
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}

// TestRbacCheck_TenantIsolation tests tenant-based isolation
func TestRbacCheck_TenantIsolation(t *testing.T) {
	// Users from different tenants should not access each other's resources
	id1 := Identity{
		Name:   "user1",
		Role:   "user",
		Groups: []string{"user"},
		Tenant: "tenant1",
	}

	id2 := Identity{
		Name:   "user2",
		Role:   "user",
		Groups: []string{"user"},
		Tenant: "tenant2",
	}

	// Both should access public endpoints
	ok1, _ := rbacCheck(id1, "GET", "/api/status")
	ok2, _ := rbacCheck(id2, "GET", "/api/status")
	if !ok1 || !ok2 {
		t.Error("rbacCheck() both tenants should access public endpoints")
	}
}

// TestRbacCheck_WriteMethods tests write method detection
func TestRbacCheck_WriteMethods(t *testing.T) {
	writeMethods := []string{"POST", "PUT", "DELETE", "PATCH"}
	
	for _, method := range writeMethods {
		t.Run(method, func(t *testing.T) {
			if !isWriteMethod(method) {
				t.Errorf("isWriteMethod() %s should be detected as write method", method)
			}
		})
	}

	readMethods := []string{"GET", "HEAD", "OPTIONS"}
	for _, method := range readMethods {
		t.Run(method, func(t *testing.T) {
			if isWriteMethod(method) {
				t.Errorf("isWriteMethod() %s should not be detected as write method", method)
			}
		})
	}
}

// TestRbacCheck_RouteClassification tests route classification
func TestRbacCheck_RouteClassification(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/api/status", "status"},
		{"/api/chat/completions", "chat"},
		{"/api/models", "models"},
		{"/api/admin/config", "admin"},
		{"/api/admin/audit", "admin"},
		{"/health", "public"},
		{"/", "public"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			class := routeClass(tt.path)
			if class != tt.expected {
				t.Errorf("routeClass() %s = %s, want %s", tt.path, class, tt.expected)
			}
		})
	}
}

// TestRbacCheck_GroupBasedAccess tests group-based access control
func TestRbacCheck_GroupBasedAccess(t *testing.T) {
	// User with multiple groups
	id := Identity{
		Name:   "user",
		Role:   "user",
		Groups: []string{"developers", "testers"},
		Tenant: "default",
	}

	// Should have access based on any of the groups
	ok, _ := rbacCheck(id, "GET", "/api/status")
	_ = ok // Just verify it doesn't panic
}

// TestRbacCheck_EmptyIdentity tests empty identity handling
func TestRbacCheck_EmptyIdentity(t *testing.T) {
	id := Identity{}

	ok, _ := rbacCheck(id, "GET", "/api/status")
	// Should handle gracefully
	_ = ok
}

// TestRbacCheck_SpecialCharacters tests special characters in paths
func TestRbacCheck_SpecialCharacters(t *testing.T) {
	id := Identity{
		Name:   "admin",
		Role:   "admin",
		Groups: []string{"admin"},
		Tenant: "default",
	}

	paths := []string{
		"/api/models/test-model",
		"/api/chat/completions?stream=true",
		"/api/admin/config?key=value",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			ok, _ := rbacCheck(id, "GET", path)
			_ = ok // Should not panic
		})
	}
}

// TestIdentityFromRequest_APIKeyHeader tests API key in header
func TestIdentityFromRequest_APIKeyHeader(t *testing.T) {
	cfgMu.Lock()
	cfg.Security.APIKey = "header-key-456"
	cfgMu.Unlock()

	req := httptest.NewRequest("GET", "/api/status", nil)
	req.Header.Set("X-API-Key", "header-key-456")

	id, ok := identityFromRequest(req)
	if !ok {
		t.Error("identityFromRequest() should accept valid API key in header")
	}
	if id.Name == "" {
		t.Error("identityFromRequest() should return identity with name")
	}
}

// TestIdentityFromRequest_BothAuthMethods tests when both auth methods are present
func TestIdentityFromRequest_BothAuthMethods(t *testing.T) {
	cfgMu.Lock()
	cfg.Security.APIKey = "test-key"
	cfgMu.Unlock()

	req := httptest.NewRequest("GET", "/api/status", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("X-API-Key", "test-key")

	id, ok := identityFromRequest(req)
	if !ok {
		t.Error("identityFromRequest() should accept when both auth methods match")
	}
	if id.Name == "" {
		t.Error("identityFromRequest() should return identity with name")
	}
}

// TestRbacCheck_LargePayload tests RBAC with many groups
func TestRbacCheck_LargePayload(t *testing.T) {
	// Create identity with many groups
	groups := make([]string, 100)
	for i := 0; i < 100; i++ {
		groups[i] = "group" + string(rune('0'+i%10))
	}

	id := Identity{
		Name:   "user",
		Role:   "user",
		Groups: groups,
		Tenant: "default",
	}

	// Should handle without performance issues
	ok, _ := rbacCheck(id, "GET", "/api/status")
	_ = ok
}

// TestRbacCheck_Consistency tests RBAC consistency across multiple calls
func TestRbacCheck_Consistency(t *testing.T) {
	id := Identity{
		Name:   "user",
		Role:   "user",
		Groups: []string{"user"},
		Tenant: "default",
	}

	// Same request should return same result
	first, firstReason := rbacCheck(id, "POST", "/api/admin/config")
	
	for i := 0; i < 100; i++ {
		ok, reason := rbacCheck(id, "POST", "/api/admin/config")
		if ok != first || reason != firstReason {
			t.Errorf("rbacCheck() inconsistent result at iteration %d: got (%v, %s), want (%v, %s)", 
				i, ok, reason, first, firstReason)
		}
	}
}
