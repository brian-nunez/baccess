package main

import (
	"brian-nunez/baccess/pkg/auth"
	"brian-nunez/baccess/pkg/predicates"
	"fmt"
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
	ID      string
	OwnerID string
	Public  bool
}

func (d Document) GetOwnerID() any {
	return d.OwnerID
}

func IsPublic() predicates.Predicate[auth.AccessRequest[User, Document]] {
	return func(req auth.AccessRequest[User, Document]) bool {
		return req.Resource.Public
	}
}

func main() {
	rbac := auth.NewRBAC[User, Document](map[string][]string{
		"admin":     {"editor"},
		"editor":    {"viewer"},
		"viewer":    {},
		"guest":     {},
		"developer": {"editor"},
	})

	evaluator := auth.NewEvaluator[User, Document]()

	isEditor := rbac.HasRole("editor")
	isOwner := auth.IsOwner[User, Document]()
	isPublic := IsPublic()

	readPolicy := isEditor.Or(isOwner).Or(isPublic)
	evaluator.AddPolicy("read", readPolicy)

	isAdmin := rbac.HasRole("admin")
	// highTrust := auth.AttrGreaterThan[User, Document]("trust_score", 80)
	deletePolicy := isAdmin.Or(isOwner)
	evaluator.AddPolicy("delete", deletePolicy)

	adminUser := User{ID: "u1", Roles: []string{"admin"}, Attrs: map[string]any{"trust_score": 90}}
	guestUser := User{ID: "u2", Roles: []string{"developer"}, Attrs: map[string]any{"trust_score": 50}}

	doc := Document{ID: "d1", OwnerID: "u2", Public: false}

	req1 := auth.AccessRequest[User, Document]{Subject: adminUser, Resource: doc, Action: "read"}
	fmt.Printf("Admin read (via hierarchy): %v\n", evaluator.Evaluate(req1))

	req2 := auth.AccessRequest[User, Document]{Subject: guestUser, Resource: doc, Action: "read"}
	fmt.Printf("Owner read: %v\n", evaluator.Evaluate(req2))

	req3 := auth.AccessRequest[User, Document]{Subject: guestUser, Resource: doc, Action: "delete"}
	fmt.Printf("Guest delete: %v\n", evaluator.Evaluate(req3))

	req4 := auth.AccessRequest[User, Document]{Subject: adminUser, Resource: doc, Action: "delete"}
	fmt.Printf("Admin delete: %v\n", evaluator.Evaluate(req4))
}
