package auth

import (
	"fmt"

	"github.com/brian-nunez/baccess/pkg/predicates"
)

type Registry[S any, R any] struct {
	preds map[string]predicates.Predicate[AccessRequest[S, R]]
}

func NewRegistry[S any, R any]() *Registry[S, R] {
	return &Registry[S, R]{
		preds: make(map[string]predicates.Predicate[AccessRequest[S, R]]),
	}
}

func (r *Registry[S, R]) Register(name string, p predicates.Predicate[AccessRequest[S, R]]) {
	r.preds[name] = p
}

func (r *Registry[S, R]) GetPredicate(name string) (predicates.Predicate[AccessRequest[S, R]], error) {
	if p, ok := r.preds[name]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("predicate not found: %s", name)
}
