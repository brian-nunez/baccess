package main

import (
	"fmt"
	"github.com/brian-nunez/baccess"
)

type User struct {
	Roles []string
}

func (u User) GetRoles() []string { return u.Roles }

type System struct{}

func main() {
	cfgData := map[string]any{
		"policies": map[string]any{
			"superuser": map[string]any{
				"allow": []string{"*"}, // Can do ANY action
			},
			"auditor": map[string]any{
				"allow": []string{"read:*"}, // Can read ANYTHING (wildcard condition)
			},
		},
	}
	cfg, _ := baccess.LoadConfigFromMap(cfgData)

	rbac := baccess.NewRBAC[User, System]()
	registry := baccess.NewRegistry[User, System]()

	evaluator, _ := baccess.BuildEvaluator(cfg, rbac, registry)

	super := User{Roles: []string{"superuser"}}
	auditor := User{Roles: []string{"auditor"}}
	sys := System{}

	fmt.Printf("Superuser nuke: %v\n", evaluator.Evaluate(baccess.AccessRequest[User, System]{Subject: super, Resource: sys, Action: "nuke"}))
	fmt.Printf("Auditor nuke:   %v\n", evaluator.Evaluate(baccess.AccessRequest[User, System]{Subject: auditor, Resource: sys, Action: "nuke"}))
	fmt.Printf("Auditor read:   %v\n", evaluator.Evaluate(baccess.AccessRequest[User, System]{Subject: auditor, Resource: sys, Action: "read"}))
}
