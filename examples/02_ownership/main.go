package main

import (
	"fmt"
	"github.com/brian-nunez/baccess"
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
	cfg, _ := baccess.LoadConfigFromMap(cfgData)

	rbac := baccess.NewRBAC[User, Document]()
	registry := baccess.NewRegistry[User, Document]()

	// Register "isOwner" predicate
	registry.Register("isOwner", baccess.FieldEquals(
		func(u User) string { return u.ID },
		func(d Document) string { return d.OwnerID },
	))

	evaluator, _ := baccess.BuildEvaluator(cfg, rbac, registry)

	alice := User{ID: "alice", Roles: []string{"user"}}
	bob := User{ID: "bob", Roles: []string{"user"}}
	doc := Document{OwnerID: "alice", Content: "Alice's Diary"}

	fmt.Printf("Alice edit Alice's doc: %v\n", evaluator.Evaluate(baccess.AccessRequest[User, Document]{Subject: alice, Resource: doc, Action: "edit:isOwner"}))
	fmt.Printf("Bob edit Alice's doc:   %v\n", evaluator.Evaluate(baccess.AccessRequest[User, Document]{Subject: bob, Resource: doc, Action: "edit:isOwner"}))
}
