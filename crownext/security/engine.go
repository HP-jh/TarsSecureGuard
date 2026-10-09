// engine.go — Security Score Engine for TSG.
// Calculates a composite security score from dynamic and static dimensions.
package security

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"
)

// Dimension defines a single scoring axis.
type Dimension struct {
	Name        string  `json:"name"`
	Score       float64 `json:"score"`        // 0–100
	Weight      float64 `json:"weight"`       // contribution to total
	Description string  `json:"description"`
	Details     string  `json:"details"`
}

// Report is the aggregated security evaluation result.
type Report struct {
	TotalScore   float64       `json:"total_score"`
	Grade        string        `json:"grade"`       // A+/A/B/C/D/F
	Dimensions   []Dimension   `json:"dimensions"`
	GeneratedAt  time.Time     `json:"generated_at"`
	Version      string        `json:"version"`
	Recommendations []string   `json:"recommendations"`
}

// ScoreEngine aggregates scores from multiple evaluators.
type ScoreEngine struct {
	mu         sync.RWMutex
	dims       []Dimension
	evaluators []Evaluator
	lastReport *Report
}

// Evaluator is a component that can produce a Dimension score.
type Evaluator interface {
	Name() string
	Weight() float64
	Evaluate(ctx context.Context) (Dimension, error)
}

// NewScoreEngine creates a new score engine.
func NewScoreEngine() *ScoreEngine {
	return &ScoreEngine{
		dims: make([]Dimension, 0),
	}
}

// RegisterEvaluator adds an evaluator.
func (e *ScoreEngine) RegisterEvaluator(ev Evaluator) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.evaluators = append(e.evaluators, ev)
}

// Evaluate runs all registered evaluators and produces a Report.
func (e *ScoreEngine) Evaluate(ctx context.Context) (*Report, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	report := &Report{
		Dimensions:   make([]Dimension, 0, len(e.evaluators)),
		GeneratedAt:  time.Now(),
		Version:      "4.3.0",
		Recommendations: make([]string, 0),
	}

	var totalWeight, weightedSum float64
	for _, ev := range e.evaluators {
		dim, err := ev.Evaluate(ctx)
		if err != nil {
			dim = Dimension{
				Name:        ev.Name(),
				Score:       0,
				Weight:      ev.Weight(),
				Description: "评估失败",
				Details:     err.Error(),
			}
		}
		dim.Weight = ev.Weight()
		report.Dimensions = append(report.Dimensions, dim)
		weightedSum += dim.Score * dim.Weight
		totalWeight += dim.Weight
		if dim.Score < 60 {
			report.Recommendations = append(report.Recommendations,
				fmt.Sprintf("[%s] 得分 %.0f/100，建议优化：%s", dim.Name, dim.Score, dim.Description))
		}
	}

	if totalWeight > 0 {
		report.TotalScore = weightedSum / totalWeight
	}
	report.Grade = scoreToGrade(report.TotalScore)
	e.lastReport = report
	return report, nil
}

// LastReport returns the most recent report.
func (e *ScoreEngine) LastReport() *Report {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.lastReport
}

func scoreToGrade(s float64) string {
	switch {
	case s >= 95:
		return "A+"
	case s >= 85:
		return "A"
	case s >= 75:
		return "B"
	case s >= 60:
		return "C"
	case s >= 40:
		return "D"
	default:
		return "F"
	}
}

// NormalizeScore clamps and rounds a raw score to 0–100.
func NormalizeScore(v float64) float64 {
	return math.Round(math.Max(0, math.Min(100, v)))
}
