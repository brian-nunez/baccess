package main

import (
	"fmt"
	"log"

	baccess "github.com/brian-nunez/baccess/v1"
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

func loadConfgFromFile() *baccess.Config {
	cfg, _ := baccess.LoadConfigFromFile("cmd/config.json")

	return cfg
}

func loadConfig() *baccess.Config {
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
					"edit",
					// "edit:isOwner",
					// "edit:isCollaborator",
				},
			},
			"viewer": map[string]any{
				"allow": []string{"read:*"},
			},
		},
	}

	cfg, _ := baccess.LoadConfigFromMap(cfgData)

	return cfg
}

func main() {
	rbac := baccess.NewRBAC[User, Document]()

	registry := baccess.NewRegistry[User, Document]()

	registry.Register("isOwner", baccess.FieldEquals(
		func(u User) string { return u.ID },
		func(d Document) string { return d.OwnerID },
	))

	registry.Register("isCollaborator", baccess.SubjectInResourceList(
		func(u User) string { return u.ID },
		func(d Document) []string { return d.Collaborators },
	))

	registry.Register("isPublic", baccess.ResourceMatches[User, Document, bool](
		func(d Document) bool { return d.Public },
		true,
	))

	cfg := loadConfgFromFile() // or loadConfig()

	evaluator, err := baccess.BuildEvaluator(cfg, rbac, registry)
	if err != nil {
		log.Fatalf("Error building evaluator: %v", err)
	}

	// admin := User{ID: "admin1", Roles: []string{"admin"}}
	editor := User{ID: "editor1", Roles: []string{"editor"}}
	// editor2 := User{ID: "editor2", Roles: []string{"editor"}}
	// viewer := User{ID: "viewer1", Roles: []string{"viewer"}}
	// other := User{ID: "other1", Roles: []string{"viewer"}}

	doc1 := Document{
		ID:            "doc1",
		OwnerID:       "editor1",
		Public:        false,
		Collaborators: []string{"editor2"},
	}

	// fmt.Println("--- Testing Policies from Config ---")
	//
	// req1 := baccess.AccessRequest[User, Document]{Subject: admin, Resource: doc1, Action: "read"}
	// fmt.Printf("Admin read doc1: %v (Expected: true)\n", evaluator.Evaluate(req1))
	//
	// req2 := baccess.AccessRequest[User, Document]{Subject: editor, Resource: doc1, Action: "read"}
	// fmt.Printf("Editor read doc1: %v (Expected: true)\n", evaluator.Evaluate(req2))
	//
	// req3 := baccess.AccessRequest[User, Document]{Subject: viewer, Resource: doc1, Action: "read"}
	// fmt.Printf("Viewer read doc1: %v (Expected: true)\n", evaluator.Evaluate(req3))
	//
	// req4 := baccess.AccessRequest[User, Document]{Subject: editor, Resource: doc1, Action: "delete"}
	// fmt.Printf("Editor delete own doc1: %v (Expected: true)\n", evaluator.Evaluate(req4))
	//
	// req5 := baccess.AccessRequest[User, Document]{Subject: other, Resource: doc1, Action: "delete"}
	// fmt.Printf("Viewer delete doc1: %v (Expected: false)\n", evaluator.Evaluate(req5))
	//
	// req6 := baccess.AccessRequest[User, Document]{Subject: admin, Resource: doc1, Action: "delete"}
	// fmt.Printf("Admin delete doc1: %v (Expected: true)\n", evaluator.Evaluate(req6))
	//
	// req7 := baccess.AccessRequest[User, Document]{Subject: admin, Resource: doc1, Action: "nuke"}
	// fmt.Printf("Admin nuke doc1: %v (Expected: true, wildcards apply)\n", evaluator.Evaluate(req7))
	//
	// req8 := baccess.AccessRequest[User, Document]{Subject: editor, Resource: doc1, Action: "nuke"}
	// fmt.Printf("Editor nuke doc1: %v (Expected: false)\n", evaluator.Evaluate(req8))

	req9 := baccess.AccessRequest[User, Document]{Subject: editor, Resource: doc1, Action: "edit:isOwner"}
	fmt.Printf("Editor1 edit own doc1: %v (Expected: true)\n", evaluator.Evaluate(req9))

	// req10 := baccess.AccessRequest[User, Document]{Subject: editor2, Resource: doc1, Action: "edit"}
	// fmt.Printf("Editor2 edit shared doc1: %v (Expected: true)\n", evaluator.Evaluate(req10))
	//
	// req11 := baccess.AccessRequest[User, Document]{Subject: other, Resource: doc1, Action: "edit"}
	// fmt.Printf("Other edit doc1: %v (Expected: false)\n", evaluator.Evaluate(req11))
}
