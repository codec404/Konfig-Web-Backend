package mailer

import (
	"bytes"
	"embed"
	"html/template"
	"strings"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

// base is parsed once; each render clones it and layers a page template on top.
var baseTemplate = template.Must(template.ParseFS(templateFS, "templates/base.html"))

// render clones the base, parses the named page template, and executes "base".
func render(page string, data any) (string, error) {
	t, err := baseTemplate.Clone()
	if err != nil {
		return "", err
	}
	if _, err = t.ParseFS(templateFS, "templates/"+page+".html"); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err = t.ExecuteTemplate(&buf, "base", data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ── Per-template data structs & render helpers ────────────────────────────────

type otpData struct {
	Subject string
	Year    int
	Digits  []string
}

func RenderOTP(code string) (string, error) {
	digits := strings.Split(code, "")
	return render("otp", otpData{
		Subject: "Your Konfig verification code",
		Year:    time.Now().Year(),
		Digits:  digits,
	})
}

type inviteData struct {
	Subject     string
	Year        int
	OrgName     string
	InviterName string
	AcceptURL   string
}

func RenderInvite(orgName, inviterName, acceptURL string) (string, error) {
	return render("invite", inviteData{
		Subject:     "You've been invited to join " + orgName + " on Konfig",
		Year:        time.Now().Year(),
		OrgName:     orgName,
		InviterName: inviterName,
		AcceptURL:   acceptURL,
	})
}

type bugReportData struct {
	Subject       string
	Year          int
	TypeLabel     string
	TypeColor     string
	TypeBg        string
	Title         string
	ReporterEmail string
	Description   string
}

var issueTypeMeta = map[string][3]string{
	"bug":             {"Bug", "#ef4444", "rgba(239,68,68,0.12)"},
	"feature_request": {"Feature Request", "#6366f1", "rgba(99,102,241,0.12)"},
	"performance":     {"Performance", "#f59e0b", "rgba(245,158,11,0.12)"},
	"ui_ux":           {"UI / UX", "#22c55e", "rgba(34,197,94,0.12)"},
	"security":        {"Security", "#a855f7", "rgba(168,85,247,0.12)"},
	"other":           {"Other", "#888899", "rgba(136,136,153,0.12)"},
}

func RenderBugReport(issueType, title, description, reporterEmail string) (string, error) {
	meta, ok := issueTypeMeta[issueType]
	if !ok {
		meta = issueTypeMeta["other"]
	}
	return render("bug_report", bugReportData{
		Subject:       "New Report: " + title,
		Year:          time.Now().Year(),
		TypeLabel:     meta[0],
		TypeColor:     meta[1],
		TypeBg:        meta[2],
		Title:         title,
		ReporterEmail: reporterEmail,
		Description:   description,
	})
}
