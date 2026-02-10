package baccess

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

type RolePolicyConfig struct {
	Allow []string `json:"allow"`
}

type Config struct {
	Policies map[string]RolePolicyConfig `json:"policies"`
}

func LoadConfigFromFile(path string) (*Config, error) {
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

func LoadConfigFromMap(data map[string]any) (*Config, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config data: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(jsonData, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	return &cfg, nil
}

type PredicateProvider[S any, R any] interface {
	GetPredicate(name string) (Predicate[AccessRequest[S, R]], error)
}

func BuildEvaluator[S RoleBearer, R any](
	cfg *Config,
	rbac *RBAC[S, R],
	provider PredicateProvider[S, R],
) (*Evaluator[S, R], error) {
	evaluator := NewEvaluator[S, R]()
	var errs error

	alwaysTrue := func(req AccessRequest[S, R]) bool { return true }

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

			var conditionPred Predicate[AccessRequest[S, R]]

			if conditionName == "*" {
				conditionPred = alwaysTrue
			} else {
				p, err := provider.GetPredicate(conditionName)
				if err != nil {
					errs = errors.Join(errs, fmt.Errorf("role '%s': rule '%s': failed to get predicate '%s': %w", role, allowRule, conditionName, err))
					conditionPred = Deny[S, R]()
				} else {
					conditionPred = p
				}
			}

			// Combine: Subject has Role AND Condition is Met
			// Use RBAC to check role (supporting hierarchy)
			rolePred := rbac.HasRole(role)
			fullPred := rolePred.And(conditionPred)

			// Register policy
			// The key for the policy map should be the full action rule if it contains a condition,
			// otherwise just the action.
			// Register policy
			policyKey := action
			if allowRule == "*" || (action == "*" && conditionName == "*") {
				policyKey = "*"
			} else if len(parts) > 1 {
				policyKey = allowRule
			}
			evaluator.AddPolicy(policyKey, fullPred)
		}
	}

	return evaluator, errs
}
