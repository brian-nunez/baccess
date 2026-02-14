package main

import (
	"fmt"
	baccess "github.com/brian-nunez/baccess/v1"
)

type User struct {
	Roles []string
}

func (u User) GetRoles() []string { return u.Roles }

type Article struct {
	State string // "draft", "published"
}

func main() {
	cfgData := map[string]any{
		"policies": map[string]any{
			"editor": map[string]any{
				"allow": []string{"edit:isDraft"},
			},
			"viewer": map[string]any{
				"allow": []string{"read:isPublished"},
			},
		},
	}
	cfg, _ := baccess.LoadConfigFromMap(cfgData)

	rbac := baccess.NewRBAC[User, Article]()
	registry := baccess.NewRegistry[User, Article]()

	resourceIsDraft := baccess.ResourceMatches[User, Article](func(a Article) string { return a.State }, "draft")
	resourceIsPublished := baccess.ResourceMatches[User, Article](func(a Article) string { return a.State }, "published")

	registry.Register("isDraft", resourceIsDraft)
	registry.Register("isPublished", resourceIsPublished)

	evaluator, _ := baccess.BuildEvaluator(cfg, rbac, registry)

	editor := User{Roles: []string{"editor"}}
	viewer := User{Roles: []string{"viewer"}}

	draft := Article{State: "draft"}
	pub := Article{State: "published"}

	fmt.Printf("Editor edit Draft:      %v\n", evaluator.Evaluate(baccess.AccessRequest[User, Article]{Subject: editor, Resource: draft, Action: "edit:isDraft"}))
	fmt.Printf("Editor edit Published:  %v\n", evaluator.Evaluate(baccess.AccessRequest[User, Article]{Subject: editor, Resource: pub, Action: "edit:isDraft"}))
	fmt.Printf("Viewer read Published:  %v\n", evaluator.Evaluate(baccess.AccessRequest[User, Article]{Subject: viewer, Resource: pub, Action: "read:isPublished"}))
	fmt.Printf("Viewer read Draft:      %v\n", evaluator.Evaluate(baccess.AccessRequest[User, Article]{Subject: viewer, Resource: draft, Action: "read:isPublished"}))
}
