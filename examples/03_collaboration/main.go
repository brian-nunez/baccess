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

type Project struct {
	TeamIDs []string
}

func main() {
	cfgData := map[string]any{
		"policies": map[string]any{
			"developer": map[string]any{
				"allow": []string{"commit:isTeamMember"},
			},
		},
	}
	cfg, _ := baccess.LoadConfigFromMap(cfgData)

	rbac := baccess.NewRBAC[User, Project]()
	registry := baccess.NewRegistry[User, Project]()

	// Check if User ID is in Project's Team list
	registry.Register("isTeamMember", baccess.SubjectInResourceList(
		func(u User) string { return u.ID },
		func(p Project) []string { return p.TeamIDs },
	))

	evaluator, _ := baccess.BuildEvaluator(cfg, rbac, registry)

	dev := User{ID: "dev1", Roles: []string{"developer"}}
	outsider := User{ID: "dev2", Roles: []string{"developer"}}

	proj := Project{TeamIDs: []string{"dev1", "lead1"}}

	fmt.Printf("Dev1 commit:   %v\n", evaluator.Evaluate(baccess.AccessRequest[User, Project]{Subject: dev, Resource: proj, Action: "commit:isTeamMember"}))
	fmt.Printf("Dev2 commit:   %v\n", evaluator.Evaluate(baccess.AccessRequest[User, Project]{Subject: outsider, Resource: proj, Action: "commit:isTeamMember"}))
}
