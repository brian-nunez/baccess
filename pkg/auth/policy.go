package auth

import "brian-nunez/baccess/pkg/predicates"

type Evaluator[S any, R any] struct {
	policies map[string]predicates.Predicate[AccessRequest[S, R]]
}

func NewEvaluator[S any, R any]() *Evaluator[S, R] {
	return &Evaluator[S, R]{
		policies: make(map[string]predicates.Predicate[AccessRequest[S, R]]),
	}
}

func (e *Evaluator[S, R]) AddPolicy(action string, p predicates.Predicate[AccessRequest[S, R]]) {
	e.policies[action] = p
}

// Evaluate checks if the access request is allowed by the registered policies.
// Returns false if no policy is found for the action (deny by default).
func (e *Evaluator[S, R]) Evaluate(req AccessRequest[S, R]) bool {
	p, ok := e.policies[req.Action]
	if !ok {
		return false
	}

	return p.IsSatisfiedBy(req)
}
