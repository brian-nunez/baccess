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
	if existing, ok := e.policies[action]; ok {
		e.policies[action] = existing.Or(p)
	} else {
		e.policies[action] = p
	}
}

func (e *Evaluator[S, R]) Evaluate(req AccessRequest[S, R]) bool {
	// Check specific policy
	if p, ok := e.policies[req.Action]; ok {
		if p.IsSatisfiedBy(req) {
			return true
		}
	}

	// Check wildcard policy
	if p, ok := e.policies["*"]; ok {
		if p.IsSatisfiedBy(req) {
			return true
		}
	}

	return false
}

