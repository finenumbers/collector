package redact

import (
	"strings"
	"testing"
)

func TestTextRedactsRadiusAndAVPairSecrets(t *testing.T) {
	input := `User-Password="hunter2" CHAP-Password=abcd Cisco-AVPair="api_key=secret-token" Authorization: Bearer abc.def`
	output := Text(input)
	for _, secret := range []string{"hunter2", "abcd", "secret-token", "abc.def"} {
		if strings.Contains(output, secret) {
			t.Fatalf("secret %q remained in %q", secret, output)
		}
	}
	if !strings.Contains(output, "Cisco-AVPair") {
		t.Fatalf("non-secret structure was removed: %q", output)
	}
}

func TestSecretNameCoverage(t *testing.T) {
	for _, name := range []string{
		"Password", "User-Password", "CHAP-Challenge", "Digest-Response",
		"preimage", "Request-Authenticator", "access_token", "credential",
		"Authorization", "api-key", "private_key", "shared-secret",
	} {
		if !SecretName(name) {
			t.Errorf("SecretName(%q) = false", name)
		}
	}
	if SecretName("User-Name") {
		t.Error("User-Name must remain usable for correlation")
	}
}
