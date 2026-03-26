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
// If APIKey is empty it logs OTPs to stdout instead (convenient for local dev).
type Mailer struct {
	apiKey string
	from   string
}

func New(apiKey, from string) *Mailer {
	return &Mailer{apiKey: apiKey, from: from}
}

// SendOTP sends a one-time password email for login.
func (m *Mailer) SendOTP(to, code, purpose string) error {
	subject := "Your Konfig verification code"
	body := fmt.Sprintf(
		"Hello,\n\nYour Konfig login OTP is:\n\n    %s\n\nThe code expires in 15 minutes.",
		code,
	)

	if m.apiKey == "" {
		log.Printf("[MAILER] OTP for %s (purpose=%s): %s", to, purpose, code)
		return nil
	}
	return m.send(to, subject, body)
}

func (m *Mailer) SendInvite(to, orgName, inviterName, token, appURL string) error {
	subject := fmt.Sprintf("You've been invited to join %s on Konfig", orgName)
	acceptURL := appURL + "/invites/" + token
	body := fmt.Sprintf(
		"Hello,\n\n%s has invited you to join the organization \"%s\" on Konfig.\n\nClick the link below to accept:\n\n    %s\n\nThis invite expires in 7 days. If you didn't expect this email, you can safely ignore it.",
		inviterName, orgName, acceptURL,
	)
	return m.send(to, subject, body)
}

func (m *Mailer) send(to, subject, body string) error {
	payload := map[string]any{
		"from":    m.from,
		"to":      []string{to},
		"subject": subject,
		"text":    body,
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
