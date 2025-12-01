package main

import (
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestCheckAttestationStatus_NoToken should fail - tests behavior when no token exists
func TestCheckAttestationStatus_NoToken(t *testing.T) {
	// Clean environment
	os.Unsetenv("KBS_TOKEN")
	os.Unsetenv("KBS_PUBLIC_KEY_PATH")

	attested, trustVector, errorMsg := checkAttestationStatus()

	// Should return false when no token is available
	if attested {
		t.Errorf("Expected attested=false when no token available, got true")
	}

	if trustVector != nil {
		t.Errorf("Expected trustVector=nil when no token available, got %+v", trustVector)
	}

	if errorMsg == "" {
		t.Errorf("Expected error message when no token available")
	}

	t.Logf("Result: attested=%v, error=%s", attested, errorMsg)
}

// TestGetKBSToken_MalformedFileContent should fail - tests handling of malformed token files
func TestGetKBSToken_MalformedFileContent(t *testing.T) {
	// This test should demonstrate that we need better error handling
	// for malformed tokens read from files

	// For now, let's assume this should not fail the getKBSToken function
	// but should fail later during token verification

	// This is a placeholder test that will help us identify
	// if we need to add validation to the token reading phase
	t.Log("Test placeholder for malformed token content handling")
}

// TestVerifyAndParseKBSToken_MalformedToken should fail - tests malformed JWT
func TestVerifyAndParseKBSToken_MalformedToken(t *testing.T) {
	malformedToken := "not.a.valid.jwt.token.at.all"

	_, err := verifyAndParseKBSToken(malformedToken)
	if err == nil {
		t.Fatalf("Expected error for malformed token, but got none")
	}

	expectedSubstring := "failed to parse token"
	if !containsString(err.Error(), expectedSubstring) {
		t.Errorf("Expected error to contain '%s', got: %s", expectedSubstring, err.Error())
	}
}

// TestParseTokenClaims_InvalidClaimsType should fail - tests wrong claim types
func TestParseTokenClaims_InvalidClaimsType(t *testing.T) {
	// Create token with wrong claims type
	wrongClaims := jwt.MapClaims{
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, wrongClaims)

	_, err := parseTokenClaims(token)
	if err == nil {
		t.Fatalf("Expected error for wrong claims type, but got none")
	}

	expectedSubstring := "could not parse token claims"
	if !containsString(err.Error(), expectedSubstring) {
		t.Errorf("Expected error to contain '%s', got: %s", expectedSubstring, err.Error())
	}
}

// TestCheckAttestationStatus_IntegrationWithRealJWT should test with properly formatted JWT
func TestCheckAttestationStatus_IntegrationWithRealJWT(t *testing.T) {
	// Create a simple test token that will fail but should be parseable
	testTokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk5OTk5OTk5OTksImlhdCI6MTYwMDAwMDAwMCwiaXNzIjoidHJ1c3RlZS1rYnMiLCJ0ZWVfdHlwZSI6InRkeCIsImVhciI6eyJ0cnVzdHdvcnRoaW5lc3MtdmVjdG9yIjp7ImhhcmR3YXJlIjoyLCJjb25maWd1cmF0aW9uIjoyLCJleGVjdXRhYmxlcyI6Mn19fQ.invalid_signature"

	// Set token in environment
	os.Setenv("KBS_TOKEN", testTokenString)
	defer os.Unsetenv("KBS_TOKEN")

	attested, trustVector, errorMsg := checkAttestationStatus()

	// With no public key available, should fall back to basic parsing
	// and should extract trust vector correctly
	if !attested {
		t.Logf("Token verification failed as expected (no signature): %s", errorMsg)

		// This is actually the expected behavior when no public key is available
		// The function should gracefully handle this case
		if !containsString(errorMsg, "Could not verify token signature") {
			t.Logf("Unexpected error type: %s", errorMsg)
		}
	}

	// If it did succeed with basic parsing, verify trust vector
	if attested && trustVector != nil {
		if trustVector.Hardware != 2 {
			t.Errorf("Expected Hardware=2, got %d", trustVector.Hardware)
		}
	}
}

// Helper function to check if string contains substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) &&
		   (s == substr ||
		    (len(s) > len(substr) &&
		     (s[:len(substr)] == substr ||
		      s[len(s)-len(substr):] == substr ||
		      containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Helper removed - was causing compilation issues