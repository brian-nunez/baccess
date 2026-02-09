package main

import (
	"fmt"
	"github.com/brian-nunez/baccess/pkg/auth"
	"github.com/brian-nunez/baccess/pkg/config"
)

// Simple User and Resource
type User struct {
	Name  string
	Roles []string
}

func (u User) GetRoles() []string { return u.Roles }

type File struct{ Name string }

func main() {
	// Define Config in Map for simplicity (simulates JSON)
	cfgData := map[string]any{
		"policies": map[string]any{
			"admin": map[string]any{"allow": []string{"delete", "read", "random"}},
			"guest": map[string]any{"allow": []string{"read"}},
		},
	}
	cfg, _ := config.LoadConfigFromMap(cfgData)

	rbac := auth.NewRBAC[User, File]()
	registry := auth.NewRegistry[User, File]() // Empty registry, no custom predicates needed

	evaluator, _ := config.BuildEvaluator(cfg, rbac, registry)

	admin := User{Name: "Alice", Roles: []string{"admin"}}
	guest := User{Name: "Bob", Roles: []string{"guest"}}
	file := File{Name: "secret.txt"}

	fmt.Printf("Admin delete: %v\n", evaluator.Evaluate(auth.AccessRequest[User, File]{Subject: admin, Resource: file, Action: "delete"}))
	fmt.Printf("Guest delete: %v\n", evaluator.Evaluate(auth.AccessRequest[User, File]{Subject: guest, Resource: file, Action: "delete"}))
	fmt.Printf("Guest read:   %v\n", evaluator.Evaluate(auth.AccessRequest[User, File]{Subject: guest, Resource: file, Action: "read"}))
	fmt.Printf("Admin random:   %v\n", evaluator.Evaluate(auth.AccessRequest[User, File]{Subject: admin, Resource: file, Action: "random:unknown"}))
}
