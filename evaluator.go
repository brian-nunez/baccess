package baccess

import (
	"strings"
)

type Evaluator[S any, R any] struct {
	policies map[string]Predicate[AccessRequest[S, R]]
}

func NewEvaluator[S any, R any]() *Evaluator[S, R] {
	return &Evaluator[S, R]{
		policies: make(map[string]Predicate[AccessRequest[S, R]]),
	}
}

func (e *Evaluator[S, R]) AddPolicy(action string, p Predicate[AccessRequest[S, R]]) {
	if existing, ok := e.policies[action]; ok {
		e.policies[action] = existing.Or(p)
	} else {
		e.policies[action] = p
	}
}

func (e *Evaluator[S, R]) Evaluate(req AccessRequest[S, R]) bool {
	var combinedPredicate Predicate[AccessRequest[S, R]]

	reqActionBase := req.Action
	reqActionCondition := ""
	if colonIndex := strings.Index(req.Action, ":"); colonIndex != -1 {
		reqActionBase = req.Action[:colonIndex]
		reqActionCondition = req.Action[colonIndex+1:]
	}

	for policyKey, p := range e.policies {
		match := false
		policyKeyBase := policyKey
		policyKeyCondition := ""
		if colonIndex := strings.Index(policyKey, ":"); colonIndex != -1 {
			policyKeyBase = policyKey[:colonIndex]
			policyKeyCondition = policyKey[colonIndex+1:]
		}

		// Rule 1: Global wildcard policy (e.g., policy "*")
		if policyKey == "*" {
			match = true
		} else if policyKey == req.Action { // Rule 2: Exact match (e.g., "read" == "read", "delete:isOwner" == "delete:isOwner")
			match = true
		} else if policyKeyCondition == "*" && policyKeyBase == reqActionBase {
			// Rule 3: Policy with action-level wildcard matches request with same base action
			// (e.g., "update:*" matches "update:title" or "update")
			match = true
		} else if policyKeyCondition == "" && policyKeyBase == reqActionBase && reqActionCondition != "" {
			// Rule 4: Policy for a base action matches request for the same base action with a condition
			// (e.g., policy "read" matches request "read:something")
			match = true
		} else if reqActionCondition == "" && policyKeyCondition != "" && reqActionBase == policyKeyBase {
			// Rule 5: Request for a base action matches policy for the same base action with a condition
			// (e.g., request "delete" matches policy "delete:isOwner")
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
