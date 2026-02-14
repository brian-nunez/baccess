package main

import (
	"fmt"
	"github.com/brian-nunez/baccess"
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
	cfg, _ := baccess.LoadConfigFromMap(cfgData)

	rbac := baccess.NewRBAC[User, Folder]()
	registry := baccess.NewRegistry[User, Folder]()

	// Intersection: Do User.Groups and Folder.AllowedGroups overlap?
	registry.Register("commonGroups", baccess.ListIntersection(
		func(u User) []string { return u.Groups },
		func(f Folder) []string { return f.AllowedGroups },
	))

	evaluator, _ := baccess.BuildEvaluator(cfg, rbac, registry)

	engUser := User{Groups: []string{"engineering", "us-east"}, Roles: []string{"employee"}}
	salesUser := User{Groups: []string{"sales"}, Roles: []string{"employee"}}

	engFolder := Folder{AllowedGroups: []string{"engineering"}}

	fmt.Printf("Eng User Access:   %v\n", evaluator.Evaluate(baccess.AccessRequest[User, Folder]{Subject: engUser, Resource: engFolder, Action: "access:commonGroups"}))
	fmt.Printf("Sales User Access: %v\n", evaluator.Evaluate(baccess.AccessRequest[User, Folder]{Subject: salesUser, Resource: engFolder, Action: "access:commonGroups"}))
}
