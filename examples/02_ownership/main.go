package main

import (
	"fmt"
	"github.com/brian-nunez/baccess/pkg/auth"
	"github.com/brian-nunez/baccess/pkg/config"
)

type User struct {
	ID    string
	Roles []string
}

func (u User) GetRoles() []string { return u.Roles }

type Document struct {
	OwnerID string
	Content string
}

func main() {
	cfgData := map[string]any{
		"policies": map[string]any{
			"user": map[string]any{
				"allow": []string{
					"read:isOwner",
					"edit:isOwner",
				},
			},
		},
	}
	cfg, _ := config.LoadConfigFromMap(cfgData)

	rbac := auth.NewRBAC[User, Document]()
	registry := auth.NewRegistry[User, Document]()

	// Register "isOwner" predicate
	registry.Register("isOwner", auth.FieldEquals(
		func(u User) string { return u.ID },
		func(d Document) string { return d.OwnerID },
	))

	evaluator, _ := config.BuildEvaluator(cfg, rbac, registry)

	alice := User{ID: "alice", Roles: []string{"user"}}
	bob := User{ID: "bob", Roles: []string{"user"}}
	doc := Document{OwnerID: "alice", Content: "Alice's Diary"}

	fmt.Printf("Alice edit Alice's doc: %v\n", evaluator.Evaluate(auth.AccessRequest[User, Document]{Subject: alice, Resource: doc, Action: "edit"}))
	fmt.Printf("Bob edit Alice's doc:   %v\n", evaluator.Evaluate(auth.AccessRequest[User, Document]{Subject: bob, Resource: doc, Action: "edit"}))
}
