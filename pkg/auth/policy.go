package auth

import (
	"brian-nunez/baccess/pkg/predicates"
	"strings"
)

type Evaluator[S any, R any] struct {
	policies map[string]predicates.Predicate[AccessRequest[S, R]]
}

func NewEvaluator[S any, R any]() *Evaluator[S, R] {
	return &Evaluator[S, R]{
		policies: make(map[string]predicates.Predicate[AccessRequest[S, R]]),
	}
}

func (e *Evaluator[S, R]) AddPolicy(action string, p predicates.Predicate[AccessRequest[S, R]]) {
	if existing, ok := e.policies[action]; ok {
		e.policies[action] = existing.Or(p)
	} else {
		e.policies[action] = p
	}
}

func (e *Evaluator[S, R]) Evaluate(req AccessRequest[S, R]) bool {
	var combinedPredicate predicates.Predicate[AccessRequest[S, R]]

	// Iterate through all registered policies
	for policyKey, p := range e.policies {
		match := false
		reqActionBase := req.Action
		reqActionCondition := ""

		// If req.Action has a colon, split it
		if colonIndex := strings.Index(reqActionBase, ":"); colonIndex != -1 {
			reqActionBase = req.Action[:colonIndex]
			reqActionCondition = req.Action[colonIndex+1:]
		}

		policyKeyBase := policyKey
		policyKeyCondition := ""
		if colonIndex := strings.Index(policyKey, ":"); colonIndex != -1 {
			policyKeyBase = policyKey[:colonIndex]
			policyKeyCondition = policyKey[colonIndex+1:]
		}

		// Rule 1: Exact match (e.g., req "edit", policy "edit" OR req "edit:something", policy "edit:something")
		if policyKey == req.Action {
			match = true
		}

		// Rule 2: Global wildcard (e.g., policy "*")
		if policyKey == "*" {
			match = true
		}

		// Rule 3: Action prefix wildcard (e.g., policy "action:*")
		// Matches if policy is "action:*" and request is "action:something"
		if policyKeyCondition == "*" && policyKeyBase == reqActionBase && reqActionCondition != "" {
			match = true
		}

		if match {
			if combinedPredicate == nil {
				combinedPredicate = p
			} else {
				combinedPredicate = combinedPredicate.Or(p)
			}
		}
	}

	if combinedPredicate == nil {
		return false
	}

	return combinedPredicate.IsSatisfiedBy(req)
}
