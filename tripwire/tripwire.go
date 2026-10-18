// tripwire.go — main Scan pipeline, Go-native translation of promptward core.
//
// Pipeline: normalize → injection scan → exfil scan → decode-and-rescan
// Inspired by promptward (MIT) johncarmack1984.
// Adapted for TSG Kingdom architecture: Phylum=security, Class=prompt-injection.

package tripwire

// ScanConfig controls detector behaviour.
type ScanConfig struct {
	// Direction is Inbound (user→system) or Outbound (system→user/tool→system).
	Direction Direction
	// Source describes where the text originated.
	Source Source
	// MinSeverity suppresses findings below this level.
	MinSeverity Severity
	// DecodeRescan runs the secondary decode-then-rescan pass.
	DecodeRescan bool
}

// DefaultScanConfig returns sensible defaults.
func DefaultScanConfig() ScanConfig {
	return ScanConfig{
		Direction:    DirectionInbound,
		Source:       SourceUser,
		MinSeverity:  SeverityInfo,
		DecodeRescan: true,
	}
}

// Scan is the primary entry point.  It runs the full detection pipeline on
// raw text and returns aggregated findings.
func Scan(text string, cfg ScanConfig) ScanResult {
	var findings []Finding

	// --- Phase 1: normalisation ---
	n := Analyze(text)
	findings = append(findings, n.Findings...)
	normalized := n.Text

	// --- Phase 2: injection detection (inbound only) ---
	if cfg.Direction == DirectionInbound {
		inj := ScanInjection(normalized, cfg.Direction, cfg.Source)
		findings = append(findings, inj...)
	}

	// --- Phase 3: exfiltration detection ---
	exf := ScanExfil(normalized, cfg.Direction, cfg.Source)
	findings = append(findings, exf...)

	// --- Phase 4: markdown / URL exfil (outbound model output) ---
	if cfg.Direction == DirectionOutbound || cfg.Source == SourceModelOutput || cfg.Source == SourceTool {
		md := ScanMarkdown(text, cfg.Source)
		findings = append(findings, md...)
	}

	// --- Phase 5: decode candidates and rescan ---
	if cfg.DecodeRescan {
		decoded := DecodeCandidates(text)
		for _, d := range decoded {
			// Only rescan if decoding produced printable text
			if _, ok := texty([]byte(d.Text)); !ok {
				continue
			}
			// Re-run injection on decoded payload
			if cfg.Direction == DirectionInbound {
				inj2 := ScanInjection(d.Text, cfg.Direction, cfg.Source)
				// Annotate that these came from an encoded layer
				for i := range inj2 {
					inj2[i].Detail = "[decoded " + d.Kind + "] " + inj2[i].Detail
					inj2[i].Score = minF64(inj2[i].Score+0.05, 1.0)
				}
				findings = append(findings, inj2...)
			}
			// Re-run exfil on decoded payload
			exf2 := ScanExfil(d.Text, cfg.Direction, cfg.Source)
			for i := range exf2 {
				exf2[i].Detail = "[decoded " + d.Kind + "] " + exf2[i].Detail
				exf2[i].Score = minF64(exf2[i].Score+0.05, 1.0)
			}
			findings = append(findings, exf2...)
		}
	}

	// --- Phase 6: deduplication ---
	findings = dedup(findings)

	// --- Phase 7: severity filtering ---
	var filtered []Finding
	for _, f := range findings {
		if f.Severity >= cfg.MinSeverity {
			filtered = append(filtered, f)
		}
	}

	// Sort by severity descending, then score descending
	for i := range filtered {
		for j := i + 1; j < len(filtered); j++ {
			if filtered[i].Severity < filtered[j].Severity ||
				(filtered[i].Severity == filtered[j].Severity && filtered[i].Score < filtered[j].Score) {
				filtered[i], filtered[j] = filtered[j], filtered[i]
			}
		}
	}

	return ScanResult{
		Findings: filtered,
		Clean:    len(filtered) == 0,
	}
}

// dedup removes exact duplicate findings.
func dedup(ff []Finding) []Finding {
	seen := make(map[string]struct{})
	var out []Finding
	for _, f := range ff {
		key := f.Label + "|" + f.Detail
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out
}

func minF64(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
