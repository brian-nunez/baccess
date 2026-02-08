package main

import (
	"brian-nunez/baccess/pkg/auth"
	"brian-nunez/baccess/pkg/config"
	"fmt"
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
	cfg, _ := config.LoadConfigFromMap(cfgData)

	rbac := auth.NewRBAC[User, System]()
	registry := auth.NewRegistry[User, System]()

	evaluator, _ := config.BuildEvaluator(cfg, rbac, registry)

	super := User{Roles: []string{"superuser"}}
	auditor := User{Roles: []string{"auditor"}}
	sys := System{}

	fmt.Printf("Superuser nuke: %v\n", evaluator.Evaluate(auth.AccessRequest[User, System]{Subject: super, Resource: sys, Action: "nuke"}))
	fmt.Printf("Auditor nuke:   %v\n", evaluator.Evaluate(auth.AccessRequest[User, System]{Subject: auditor, Resource: sys, Action: "nuke"}))
	fmt.Printf("Auditor read:   %v\n", evaluator.Evaluate(auth.AccessRequest[User, System]{Subject: auditor, Resource: sys, Action: "read"}))
}
