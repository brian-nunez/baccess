package main

import (
	"fmt"
	"github.com/brian-nunez/baccess/pkg/auth"
	"github.com/brian-nunez/baccess/pkg/config"
)

type User struct {
	Groups []string
	Roles  []string
}

func (u User) GetRoles() []string { return u.Roles }

type Folder struct {
	AllowedGroups []string
}

func main() {
	cfgData := map[string]any{
		"policies": map[string]any{
			"employee": map[string]any{
				"allow": []string{"access:commonGroups"},
			},
		},
	}
	cfg, _ := config.LoadConfigFromMap(cfgData)

	rbac := auth.NewRBAC[User, Folder]()
	registry := auth.NewRegistry[User, Folder]()

	// Intersection: Do User.Groups and Folder.AllowedGroups overlap?
	registry.Register("commonGroups", auth.ListIntersection(
		func(u User) []string { return u.Groups },
		func(f Folder) []string { return f.AllowedGroups },
	))

	evaluator, _ := config.BuildEvaluator(cfg, rbac, registry)

	engUser := User{Groups: []string{"engineering", "us-east"}, Roles: []string{"employee"}}
	salesUser := User{Groups: []string{"sales"}, Roles: []string{"employee"}}

	engFolder := Folder{AllowedGroups: []string{"engineering"}}

	fmt.Printf("Eng User Access:   %v\n", evaluator.Evaluate(auth.AccessRequest[User, Folder]{Subject: engUser, Resource: engFolder, Action: "access"}))
	fmt.Printf("Sales User Access: %v\n", evaluator.Evaluate(auth.AccessRequest[User, Folder]{Subject: salesUser, Resource: engFolder, Action: "access"}))
}
