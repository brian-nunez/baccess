package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"brian-nunez/baccess/pkg/auth"
	"brian-nunez/baccess/pkg/predicates"
)

type RolePolicyConfig struct {
	Allow []string `json:"allow"`
}

type Config struct {
	Policies map[string]RolePolicyConfig `json:"policies"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	return &cfg, nil
}

type PredicateProvider[S any, R any] interface {
	GetPredicate(name string) (predicates.Predicate[auth.AccessRequest[S, R]], error)
}

func BuildEvaluator[S auth.RoleBearer, R any](
	cfg *Config,
	rbac *auth.RBAC[S, R],
	provider PredicateProvider[S, R],
) (*auth.Evaluator[S, R], error) {
	evaluator := auth.NewEvaluator[S, R]()

	alwaysTrue := func(req auth.AccessRequest[S, R]) bool { return true }

	for role, policy := range cfg.Policies {
		for _, allowRule := range policy.Allow {
			// Parse "action:condition" or just "action" (implying always)
			parts := strings.SplitN(allowRule, ":", 2)
			action := parts[0]
			var conditionName string

			if len(parts) > 1 {
				conditionName = parts[1]
			} else {
				// If no condition specified, assume "*" (Always)
				conditionName = "*"
			}

			// Resolve the condition predicate
			var conditionPred predicates.Predicate[auth.AccessRequest[S, R]]

			if conditionName == "*" {
				conditionPred = alwaysTrue
			} else {
				p, err := provider.GetPredicate(conditionName)
				if err != nil {
					return nil, fmt.Errorf("unknown predicate '%s' in rule '%s' for role '%s'", conditionName, allowRule, role)
				}

				conditionPred = p
			}

			// Combine: Subject has Role AND Condition is Met
			// Use RBAC to check role (supporting hierarchy)
			rolePred := rbac.HasRole(role)
			fullPred := rolePred.And(conditionPred)

			// Register policy
			// If action is "*", we register it as the wildcard policy
			evaluator.AddPolicy(action, fullPred)
		}
	}

	return evaluator, nil
}
