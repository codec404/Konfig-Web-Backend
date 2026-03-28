package mailer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRenderTemplates renders every email template to a .html file in /tmp/konfig-email-previews/
// so you can open them in a browser without sending any email.
//
// Run with:
//
//	go test ./internal/mailer/... -v -run TestRenderTemplates
//
// Then open the printed paths in your browser.
func TestRenderTemplates(t *testing.T) {
	outDir := filepath.Join(os.TempDir(), "konfig-email-previews")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("could not create output dir: %v", err)
	}

	cases := []struct {
		name string
		html func() (string, error)
	}{
		{
			name: "otp.html",
			html: func() (string, error) {
				return RenderOTP("482917")
			},
		},
		{
			name: "invite.html",
			html: func() (string, error) {
				return RenderInvite("Acme Corp", "Alice", "http://localhost:5173/invites/tok_preview123")
			},
		},
		{
			name: "bug_report_bug.html",
			html: func() (string, error) {
				return RenderBugReport(
					"bug",
					"Login page crashes on mobile Safari",
					"Steps to reproduce:\n1. Open the login page on iPhone Safari 17\n2. Enter email and tap 'Send OTP'\n3. App freezes and shows a blank screen\n\nExpected: OTP sent and input shown\nActual: White screen, no error",
					"user@example.com",
				)
			},
		},
		{
			name: "bug_report_feature.html",
			html: func() (string, error) {
				return RenderBugReport(
					"feature_request",
					"Dark mode toggle in mobile nav",
					"Currently the theme toggle is only in the sidebar footer which is hidden on mobile. Please add it to the mobile top bar as well.",
					"designer@example.com",
				)
			},
		},
		{
			name: "bug_report_security.html",
			html: func() (string, error) {
				return RenderBugReport(
					"security",
					"JWT token not invalidated on logout",
					"After logging out, the old JWT can still be used to call /api/auth/me and get a valid response. Token should be revoked server-side on logout.",
					"researcher@example.com",
				)
			},
		},
	}

	t.Logf("\n\nEmail preview files written to: %s\n", outDir)

	for _, tc := range cases {
		tc := tc
		t.Run(strings.TrimSuffix(tc.name, ".html"), func(t *testing.T) {
			html, err := tc.html()
			if err != nil {
				t.Fatalf("render error: %v", err)
			}
			if strings.TrimSpace(html) == "" {
				t.Fatal("rendered HTML is empty")
			}

			out := filepath.Join(outDir, tc.name)
			if err := os.WriteFile(out, []byte(html), 0o644); err != nil {
				t.Fatalf("write error: %v", err)
			}
			t.Logf("  open file://%s", out)
		})
	}
}
