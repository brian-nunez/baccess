package main

import (
	"fmt"
	"github.com/brian-nunez/baccess/pkg/auth"
	"github.com/brian-nunez/baccess/pkg/config"
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
	cfg, _ := config.LoadConfigFromMap(cfgData)

	rbac := auth.NewRBAC[User, Article]()
	registry := auth.NewRegistry[User, Article]()

	resourceIsDraft := auth.ResourceMatches[User, Article](func(a Article) string { return a.State }, "draft")
	resourceIsPublished := auth.ResourceMatches[User, Article](func(a Article) string { return a.State }, "published")

	registry.Register("isDraft", resourceIsDraft)
	registry.Register("isPublished", resourceIsPublished)

	evaluator, _ := config.BuildEvaluator(cfg, rbac, registry)

	editor := User{Roles: []string{"editor"}}
	viewer := User{Roles: []string{"viewer"}}

	draft := Article{State: "draft"}
	pub := Article{State: "published"}

	fmt.Printf("Editor edit Draft:      %v\n", evaluator.Evaluate(auth.AccessRequest[User, Article]{Subject: editor, Resource: draft, Action: "edit"}))
	fmt.Printf("Editor edit Published:  %v\n", evaluator.Evaluate(auth.AccessRequest[User, Article]{Subject: editor, Resource: pub, Action: "edit"}))
	fmt.Printf("Viewer read Published:  %v\n", evaluator.Evaluate(auth.AccessRequest[User, Article]{Subject: viewer, Resource: pub, Action: "read"}))
	fmt.Printf("Viewer read Draft:      %v\n", evaluator.Evaluate(auth.AccessRequest[User, Article]{Subject: viewer, Resource: draft, Action: "read"}))
}
