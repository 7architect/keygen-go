package keygen

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"testing"
	"time"
)

type signedResponseHeaders struct {
	KeygenDigest string
	KeygenDate   string
	Digest       string
	Date         string
}

// newSignedResponse builds a response signed over the given digest and date,
// while letting the caller control which headers are actually set.
func newSignedResponse(t *testing.T, priv ed25519.PrivateKey, body []byte, signedDate string, headers signedResponseHeaders) *Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, "https://api.keygen.sh/v1/accounts/test/me?foo=bar", nil)
	if err != nil {
		t.Fatalf("Should not fail creating a request: err=%v", err)
	}

	shasum := sha256.Sum256(body)
	digest := "sha-256=" + base64.StdEncoding.EncodeToString(shasum[:])
	msg := fmt.Sprintf(
		"(request-target): get /v1/accounts/test/me?foo=bar\nhost: api.keygen.sh\ndate: %s\ndigest: %s",
		signedDate,
		digest,
	)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(msg)))

	h := http.Header{}
	h.Set("Keygen-Signature", fmt.Sprintf(`keyid="test", algorithm="ed25519", signature="%s", headers="(request-target) host date digest"`, sig))

	set := func(k, v string) {
		switch v {
		case "":
		case "$digest":
			h.Set(k, digest)
		default:
			h.Set(k, v)
		}
	}

	set("Keygen-Digest", headers.KeygenDigest)
	set("Keygen-Date", headers.KeygenDate)
	set("Digest", headers.Digest)
	set("Date", headers.Date)

	return &Response{Request: req, Headers: h, Body: body}
}

func TestVerifyResponseHeaders(t *testing.T) {
	prevDrift := MaxClockDrift
	t.Cleanup(func() { MaxClockDrift = prevDrift })
	MaxClockDrift = 5 * time.Minute

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Should generate a key: err=%v", err)
	}

	v := &verifier{PublicKey: hex.EncodeToString(pub)}
	body := []byte(`{"data":{"id":"1","type":"users"}}`)
	now := time.Now().UTC().Format(time.RFC1123)
	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC1123)
	recent := time.Now().Add(-2 * time.Minute).UTC().Format(time.RFC1123)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC1123)
	bogusDigest := "sha-256=" + base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))

	tests := []struct {
		name       string
		signedDate string
		headers    signedResponseHeaders
		want       error
	}{
		{
			name:       "keygen headers only",
			signedDate: now,
			headers:    signedResponseHeaders{KeygenDigest: "$digest", KeygenDate: now},
		},
		{
			name:       "standard headers only (fallback)",
			signedDate: now,
			headers:    signedResponseHeaders{Digest: "$digest", Date: now},
		},
		{
			name:       "keygen digest preferred over stripped/rewritten digest",
			signedDate: now,
			headers:    signedResponseHeaders{KeygenDigest: "$digest", KeygenDate: now, Digest: bogusDigest, Date: now},
		},
		{
			name:       "invalid keygen digest is not rescued by valid digest",
			signedDate: now,
			headers:    signedResponseHeaders{KeygenDigest: bogusDigest, KeygenDate: now, Digest: "$digest", Date: now},
			want:       ErrResponseDigestInvalid,
		},
		{
			name:       "keygen date preferred over rewritten date",
			signedDate: now,
			headers:    signedResponseHeaders{KeygenDigest: "$digest", KeygenDate: now, Date: old},
		},
		{
			name:       "date ahead of keygen date",
			signedDate: now,
			headers:    signedResponseHeaders{KeygenDigest: "$digest", KeygenDate: now, Date: future},
		},
		{
			name:       "date ahead of keygen date within clock drift",
			signedDate: recent,
			headers:    signedResponseHeaders{KeygenDigest: "$digest", KeygenDate: recent, Date: now},
		},
		{
			name:       "stale keygen date is not rescued by fresh date",
			signedDate: old,
			headers:    signedResponseHeaders{KeygenDigest: "$digest", KeygenDate: old, Date: now},
			want:       ErrResponseDateTooOld,
		},
		{
			name:       "signature is checked against keygen date",
			signedDate: old,
			headers:    signedResponseHeaders{KeygenDigest: "$digest", KeygenDate: now, Date: old},
			want:       ErrResponseSignatureInvalid,
		},
		{
			name:       "keygen digest with standard date",
			signedDate: now,
			headers:    signedResponseHeaders{KeygenDigest: "$digest", Date: now},
		},
		{
			name:       "digest missing",
			signedDate: now,
			headers:    signedResponseHeaders{KeygenDate: now, Date: now},
			want:       ErrResponseDigestMissing,
		},
		{
			name:       "date missing",
			signedDate: now,
			headers:    signedResponseHeaders{KeygenDigest: "$digest", Digest: "$digest"},
			want:       ErrResponseDateMissing,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := newSignedResponse(t, priv, body, tt.signedDate, tt.headers)

			if err := v.VerifyResponse(res); err != tt.want {
				t.Fatalf("Unexpected result: actual=%v expected=%v", err, tt.want)
			}
		})
	}
}
