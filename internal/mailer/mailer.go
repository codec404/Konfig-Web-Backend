package mailer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

const resendEndpoint = "https://api.resend.com/emails"

// Mailer sends transactional email via Resend.
// If APIKey is empty it logs to stdout instead (convenient for local dev).
type Mailer struct {
	apiKey string
	from   string
}

func New(apiKey, from string) *Mailer {
	return &Mailer{apiKey: apiKey, from: from}
}

// SendOTP sends a one-time password email for login.
func (m *Mailer) SendOTP(to, code, purpose string) error {
	if m.apiKey == "" {
		log.Printf("[MAILER] OTP for %s (purpose=%s): %s", to, purpose, code)
		return nil
	}
	html, err := RenderOTP(code)
	if err != nil {
		return err
	}
	return m.send(to, "Your Konfig verification code", html)
}

// SendInvite sends an org invitation email.
func (m *Mailer) SendInvite(to, orgName, inviterName, token, appURL string) error {
	acceptURL := appURL + "/invites/" + token
	subject := fmt.Sprintf("You've been invited to join %s on Konfig", orgName)
	if m.apiKey == "" {
		log.Printf("[MAILER] Invite for %s to org %s: %s", to, orgName, acceptURL)
		return nil
	}
	html, err := RenderInvite(orgName, inviterName, acceptURL)
	if err != nil {
		return err
	}
	return m.send(to, subject, html)
}

// SendBugReport notifies the developer of a new bug report.
func (m *Mailer) SendBugReport(to, issueType, title, description, reporterEmail string) error {
	subject := fmt.Sprintf("[Konfig] New report: %s", title)
	if m.apiKey == "" {
		log.Printf("[MAILER] Bug report to %s | type=%s | reporter=%s | %s", to, issueType, reporterEmail, title)
		return nil
	}
	html, err := RenderBugReport(issueType, title, description, reporterEmail)
	if err != nil {
		return err
	}
	return m.send(to, subject, html)
}

// send delivers an HTML email via the Resend API.
func (m *Mailer) send(to, subject, html string) error {
	payload := map[string]any{
		"from":    m.from,
		"to":      []string{to},
		"subject": subject,
		"html":    html,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, resendEndpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("resend: unexpected status %d", resp.StatusCode)
	}
	return nil
}
