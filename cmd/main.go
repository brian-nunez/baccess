package main

import (
	"fmt"
	"log"

	"brian-nunez/baccess/pkg/auth"
	"brian-nunez/baccess/pkg/config"
)

type User struct {
	ID    string
	Roles []string
	Attrs map[string]any
}

func (u User) GetID() any {
	return u.ID
}

func (u User) GetRoles() []string {
	return u.Roles
}

func (u User) GetAttribute(key string) any {
	return u.Attrs[key]
}

type Document struct {
	ID            string
	OwnerID       string
	Public        bool
	Collaborators []string
}

func loadConfgFromFile() *config.Config {
	cfg, _ := config.LoadConfigFromFile("cmd/config.json")

	return cfg
}

func loadConfig() *config.Config {
	cfgData := map[string]any{
		"policies": map[string]any{
			"admin": map[string]any{
				"allow": []string{"*"},
			},
			"editor": map[string]any{
				"allow": []string{
					"read:*",
					"write:*",
					"delete:isOwner",
					"edit:isOwner",
					"edit:isCollaborator",
				},
			},
			"viewer": map[string]any{
				"allow": []string{"read:*"},
			},
		},
	}

	cfg, _ := config.LoadConfigFromMap(cfgData)

	return cfg
}

func main() {
	rbac := auth.NewRBAC[User, Document]()

	registry := auth.NewRegistry[User, Document]()

	registry.Register("isOwner", auth.FieldEquals(
		func(u User) string { return u.ID },
		func(d Document) string { return d.OwnerID },
	))

	registry.Register("isCollaborator", auth.SubjectInResourceList(
		func(u User) string { return u.ID },
		func(d Document) []string { return d.Collaborators },
	))

	registry.Register("isPublic", auth.ResourceMatches[User, Document, bool](
		func(d Document) bool { return d.Public },
		true,
	))

	cfg := loadConfgFromFile() // or loadConfig()

	evaluator, err := config.BuildEvaluator(cfg, rbac, registry)
	if err != nil {
		log.Fatalf("Error building evaluator: %v", err)
	}

	admin := User{ID: "admin1", Roles: []string{"admin"}}
	editor := User{ID: "editor1", Roles: []string{"editor"}}
	editor2 := User{ID: "editor2", Roles: []string{"editor"}}
	viewer := User{ID: "viewer1", Roles: []string{"viewer"}}
	other := User{ID: "other1", Roles: []string{"viewer"}}

	doc1 := Document{
		ID:            "doc1",
		OwnerID:       "editor1",
		Public:        false,
		Collaborators: []string{"editor2"},
	}

	fmt.Println("--- Testing Policies from Config ---")

	req1 := auth.AccessRequest[User, Document]{Subject: admin, Resource: doc1, Action: "read"}
	fmt.Printf("Admin read doc1: %v (Expected: true)\n", evaluator.Evaluate(req1))

	req2 := auth.AccessRequest[User, Document]{Subject: editor, Resource: doc1, Action: "read"}
	fmt.Printf("Editor read doc1: %v (Expected: true)\n", evaluator.Evaluate(req2))

	req3 := auth.AccessRequest[User, Document]{Subject: viewer, Resource: doc1, Action: "read"}
	fmt.Printf("Viewer read doc1: %v (Expected: true)\n", evaluator.Evaluate(req3))

	req4 := auth.AccessRequest[User, Document]{Subject: editor, Resource: doc1, Action: "delete"}
	fmt.Printf("Editor delete own doc1: %v (Expected: true)\n", evaluator.Evaluate(req4))

	req5 := auth.AccessRequest[User, Document]{Subject: other, Resource: doc1, Action: "delete"}
	fmt.Printf("Viewer delete doc1: %v (Expected: false)\n", evaluator.Evaluate(req5))

	req6 := auth.AccessRequest[User, Document]{Subject: admin, Resource: doc1, Action: "delete"}
	fmt.Printf("Admin delete doc1: %v (Expected: true)\n", evaluator.Evaluate(req6))

	req7 := auth.AccessRequest[User, Document]{Subject: admin, Resource: doc1, Action: "nuke"}
	fmt.Printf("Admin nuke doc1: %v (Expected: true, wildcards apply)\n", evaluator.Evaluate(req7))

	req8 := auth.AccessRequest[User, Document]{Subject: editor, Resource: doc1, Action: "nuke"}
	fmt.Printf("Editor nuke doc1: %v (Expected: false)\n", evaluator.Evaluate(req8))

	req9 := auth.AccessRequest[User, Document]{Subject: editor, Resource: doc1, Action: "edit"}
	fmt.Printf("Editor1 edit own doc1: %v (Expected: true)\n", evaluator.Evaluate(req9))

	req10 := auth.AccessRequest[User, Document]{Subject: editor2, Resource: doc1, Action: "edit"}
	fmt.Printf("Editor2 edit shared doc1: %v (Expected: true)\n", evaluator.Evaluate(req10))

	req11 := auth.AccessRequest[User, Document]{Subject: other, Resource: doc1, Action: "edit"}
	fmt.Printf("Other edit doc1: %v (Expected: false)\n", evaluator.Evaluate(req11))
}
