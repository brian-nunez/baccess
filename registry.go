package baccess

import (
	"fmt"
)

type Registry[S any, R any] struct {
	preds map[string]Predicate[AccessRequest[S, R]]
}

func NewRegistry[S any, R any]() *Registry[S, R] {
	return &Registry[S, R]{
		preds: make(map[string]Predicate[AccessRequest[S, R]]),
	}
}

func (r *Registry[S, R]) Register(name string, p Predicate[AccessRequest[S, R]]) {
	r.preds[name] = p
}

func (r *Registry[S, R]) GetPredicate(name string) (Predicate[AccessRequest[S, R]], error) {
	if p, ok := r.preds[name]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("predicate not found: %s", name)
}
