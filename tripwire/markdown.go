// markdown.go — URL exfiltration scanner inspired by promptward/tripwire-core.
// Detects data smuggling through markdown links and URL-encoded payloads
// in model outputs and tool returns.
//
// MIT License. Based on promptward by johncarmack1984.

package tripwire

import (
	"net/url"
	"regexp"
	"strings"
)

// MarkdownURL captures the pieces of a markdown link [text](href).
type MarkdownURL struct {
	Text string
	Href string
}

// markdownLinkRe matches [label](href) with optional title.
var markdownLinkRe = regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)

// suspiciousSchemeRe flags non-standard or data-URI schemes.
var suspiciousSchemeRe = regexp.MustCompile(`(?i)^(javascript|data|vbscript|file):`)

// queryPayloadRe looks for long or suspicious query parameters.
var queryPayloadRe = regexp.MustCompile(`[?&][a-z0-9_]{1,3}=([A-Za-z0-9+/=]{40,}|[A-Fa-f0-9]{32,})`)

// ScanMarkdown receives outbound text (e.g. model reply) and reports any
// URLs that may be leaking secrets or encoded payloads.
func ScanMarkdown(text string, src Source) []Finding {
	var findings []Finding

	// 1. Markdown links
	links := ExtractMarkdownLinks(text)
	for _, l := range links {
		if suspiciousSchemeRe.MatchString(l.Href) {
			findings = append(findings, Finding{
				Kind:     KindExfiltration,
				Label:    "suspicious_url_scheme",
				Severity: SeverityHigh,
				Score:    0.95,
				Source:   src,
				Detail:   "suspicious scheme in URL: " + truncate(l.Href, 80),
			})
			continue
		}

		u, err := url.Parse(l.Href)
		if err == nil && u.Host != "" {
			// domain reputation: if the link text differs from the real host,
			// it may be a disguised exfiltration destination.
			if strings.Contains(l.Text, ".") && !strings.Contains(l.Href, l.Text) {
				findings = append(findings, Finding{
					Kind:     KindExfiltration,
					Label:    "disguised_link",
					Severity: SeverityHigh,
					Score:    0.85,
					Source:   src,
					Detail:   "link text claims domain but points elsewhere: " + truncate(l.Href, 80),
				})
			}
		}

		// Query-string payload detection
		if queryPayloadRe.MatchString(l.Href) {
			findings = append(findings, Finding{
				Kind:     KindExfiltration,
				Label:    "query_exfiltration_payload",
				Severity: SeverityMedium,
				Score:    0.75,
				Source:   src,
				Detail:   "possible encoded payload in URL query: " + truncate(l.Href, 80),
			})
		}
	}

	// 2. Bare URLs (not wrapped in markdown)
	bareURLs := extractBareURLs(text)
	for _, raw := range bareURLs {
		if suspiciousSchemeRe.MatchString(raw) {
			findings = append(findings, Finding{
				Kind:     KindExfiltration,
				Label:    "bare_suspicious_url",
				Severity: SeverityHigh,
				Score:    0.90,
				Source:   src,
				Detail:   "bare suspicious URL: " + truncate(raw, 80),
			})
		}
	}

	return findings
}

// ExtractMarkdownLinks returns all [text](href) pairs found in s.
func ExtractMarkdownLinks(s string) []MarkdownURL {
	var out []MarkdownURL
	matches := markdownLinkRe.FindAllStringSubmatchIndex(s, -1)
	for _, m := range matches {
		if len(m) >= 6 {
			out = append(out, MarkdownURL{
				Text: s[m[2]:m[3]],
				Href: s[m[4]:m[5]],
			})
		}
	}
	return out
}

// extractBareURLs finds http(s)://… strings outside of markdown brackets.
func extractBareURLs(s string) []string {
	// Naïve extraction; markdown links already handled above.
	var out []string
	re := regexp.MustCompile(`https?://[^\s<>"'\)\]]+`)
	for _, m := range re.FindAllString(s, -1) {
		out = append(out, m)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
