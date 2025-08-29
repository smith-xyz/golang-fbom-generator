package rules

import (
	"github.com/smith-xyz/golang-fbom-generator/pkg/config"
)

// Rules provides a convenient aggregator for rule-based components
type Rules struct {
	Classifier *Classifier
}

// NewRules creates a new Rules instance with clean configuration injection
func NewRules(contextConfig *config.ContextAwareConfig, baseConfig *config.Config) *Rules {
	return &Rules{
		Classifier: NewClassifier(contextConfig, baseConfig),
	}
}
