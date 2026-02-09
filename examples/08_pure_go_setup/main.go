package main

import (
	"fmt"
	"github.com/brian-nunez/baccess/pkg/auth"
)

type User struct {
	ID    string
	Roles []string
}

func (u User) GetRoles() []string { return u.Roles }

type Data struct {
	OwnerID string
}

func main() {
	// 1. Manually instantiate Evaluator
	evaluator := auth.NewEvaluator[User, Data]()
	rbac := auth.NewRBAC[User, Data]()

	// 2. Define Predicates
	isOwner := auth.FieldEquals(
		func(u User) string { return u.ID },
		func(d Data) string { return d.OwnerID },
	)

	hasRoleUser := rbac.HasRole("user")
	hasRoleAdmin := rbac.HasRole("admin")

	// 3. Construct Policies
	// Policy: "delete" allowed if (Admin) OR (User AND Owner)
	deletePolicy := hasRoleAdmin.Or(hasRoleUser.And(isOwner))

	// 4. Register
	evaluator.AddPolicy("delete", deletePolicy)

	// 5. Test
	admin := User{ID: "admin", Roles: []string{"admin"}}
	user := User{ID: "u1", Roles: []string{"user"}}
	data := Data{OwnerID: "u1"}

	req1 := auth.AccessRequest[User, Data]{Subject: admin, Resource: data, Action: "delete"}
	fmt.Printf("Admin delete: %v\n", evaluator.Evaluate(req1))

	req2 := auth.AccessRequest[User, Data]{Subject: user, Resource: data, Action: "delete"}
	fmt.Printf("User delete own: %v\n", evaluator.Evaluate(req2))

	data2 := Data{OwnerID: "other"}
	req3 := auth.AccessRequest[User, Data]{Subject: user, Resource: data2, Action: "delete"}
	fmt.Printf("User delete other: %v\n", evaluator.Evaluate(req3))
}
