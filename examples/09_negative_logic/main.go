package main

import (
	"fmt"
	"github.com/brian-nunez/baccess"
)

type User struct {
	Roles     []string
	Suspended bool
}

func (u User) GetRoles() []string { return u.Roles }

type Page struct{}

func main() {
	evaluator := baccess.NewEvaluator[User, Page]()
	rbac := baccess.NewRBAC[User, Page]()

	suspended := func(req baccess.AccessRequest[User, Page]) bool {
		return req.Subject.Suspended
	}

	// Policy: Must be "member" AND NOT Suspended
	policySimple := rbac.HasRole("member").And(baccess.Not(suspended))

	evaluator.AddPolicy("view", policySimple)

	active := User{Roles: []string{"member"}, Suspended: false}
	banned := User{Roles: []string{"member"}, Suspended: true}
	page := Page{}

	fmt.Printf("Active Member view: %v\n", evaluator.Evaluate(baccess.AccessRequest[User, Page]{Subject: active, Resource: page, Action: "view"}))
	fmt.Printf("Banned Member view: %v\n", evaluator.Evaluate(baccess.AccessRequest[User, Page]{Subject: banned, Resource: page, Action: "view"}))
}
