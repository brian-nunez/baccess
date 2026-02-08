package main

import (
	"brian-nunez/baccess/pkg/auth"
	"fmt"
)

type User struct {
	Roles     []string
	Suspended bool
}

func (u User) GetRoles() []string { return u.Roles }

type Page struct{}

func main() {
	evaluator := auth.NewEvaluator[User, Page]()
	rbac := auth.NewRBAC[User, Page]()

	suspended := func(req auth.AccessRequest[User, Page]) bool {
		return req.Subject.Suspended
	}

	// Policy: Must be "member" AND NOT Suspended
	policySimple := rbac.HasRole("member").And(auth.Not(suspended))

	evaluator.AddPolicy("view", policySimple)

	active := User{Roles: []string{"member"}, Suspended: false}
	banned := User{Roles: []string{"member"}, Suspended: true}
	page := Page{}

	fmt.Printf("Active Member view: %v\n", evaluator.Evaluate(auth.AccessRequest[User, Page]{Subject: active, Resource: page, Action: "view"}))
	fmt.Printf("Banned Member view: %v\n", evaluator.Evaluate(auth.AccessRequest[User, Page]{Subject: banned, Resource: page, Action: "view"}))
}
