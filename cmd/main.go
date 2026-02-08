package main

import (
	"fmt"
	"log"

	"brian-nunez/baccess/pkg/auth"
	"brian-nunez/baccess/pkg/config"
	"brian-nunez/baccess/pkg/predicates"
)

type User struct {
	ID    string
	Roles []string
	Attrs map[string]any
}

func (u User) GetID() any {
	return u.ID
}

func (u User) GetRoles() []string {
	return u.Roles
}

func (u User) GetAttribute(key string) any {
	return u.Attrs[key]
}

type Document struct {
	ID      string
	OwnerID string
	Public  bool
}

func (d Document) GetOwnerID() any {
	return d.OwnerID
}

type Registry struct {
	preds map[string]predicates.Predicate[auth.AccessRequest[User, Document]]
}

func NewRegistry() *Registry {
	return &Registry{
		preds: make(map[string]predicates.Predicate[auth.AccessRequest[User, Document]]),
	}
}

func (r *Registry) Register(name string, p predicates.Predicate[auth.AccessRequest[User, Document]]) {
	r.preds[name] = p
}

func (r *Registry) GetPredicate(name string) (predicates.Predicate[auth.AccessRequest[User, Document]], error) {
	if p, ok := r.preds[name]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("predicate not found: %s", name)
}

func main() {
	rbac := auth.NewRBAC[User, Document](map[string][]string{
		"admin":  {"editor"},
		"editor": {"viewer"},
	})

	registry := NewRegistry()
	registry.Register("isOwner", auth.IsOwner[User, Document]())
	registry.Register("isPublic", func(req auth.AccessRequest[User, Document]) bool {
		return req.Resource.Public
	})

	cfg, err := config.LoadConfig("cmd/config.json")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	evaluator, err := config.BuildEvaluator(cfg, rbac, registry)
	if err != nil {
		log.Fatalf("Error building evaluator: %v", err)
	}

	admin := User{ID: "admin1", Roles: []string{"admin"}}
	editor := User{ID: "editor1", Roles: []string{"editor"}}
	viewer := User{ID: "viewer1", Roles: []string{"viewer"}}
	other := User{ID: "other1", Roles: []string{"viewer"}}

	doc1 := Document{ID: "doc1", OwnerID: "editor1", Public: false}

	fmt.Println("--- Testing Policies from Config ---")

	req1 := auth.AccessRequest[User, Document]{Subject: admin, Resource: doc1, Action: "read"}
	fmt.Printf("Admin read doc1: %v (Expected: true)\n", evaluator.Evaluate(req1))

	req2 := auth.AccessRequest[User, Document]{Subject: editor, Resource: doc1, Action: "read"}
	fmt.Printf("Editor read doc1: %v (Expected: true)\n", evaluator.Evaluate(req2))

	req3 := auth.AccessRequest[User, Document]{Subject: viewer, Resource: doc1, Action: "read"}
	fmt.Printf("Viewer read doc1: %v (Expected: true)\n", evaluator.Evaluate(req3))

	req4 := auth.AccessRequest[User, Document]{Subject: editor, Resource: doc1, Action: "delete"}
	fmt.Printf("Editor delete own doc1: %v (Expected: true)\n", evaluator.Evaluate(req4))

	req5 := auth.AccessRequest[User, Document]{Subject: other, Resource: doc1, Action: "delete"}
	fmt.Printf("Viewer delete doc1: %v (Expected: false)\n", evaluator.Evaluate(req5))

	req6 := auth.AccessRequest[User, Document]{Subject: admin, Resource: doc1, Action: "delete"}
	fmt.Printf("Admin delete doc1: %v (Expected: true)\n", evaluator.Evaluate(req6))

	req7 := auth.AccessRequest[User, Document]{Subject: admin, Resource: doc1, Action: "nuke"}
	fmt.Printf("Admin nuke doc1: %v (Expected: true, wildcards apply)\n", evaluator.Evaluate(req7))

	req8 := auth.AccessRequest[User, Document]{Subject: editor, Resource: doc1, Action: "nuke"}
	fmt.Printf("Editor nuke doc1: %v (Expected: false)\n", evaluator.Evaluate(req8))

}
