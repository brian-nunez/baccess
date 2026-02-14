package main

import (
	"fmt"
	baccess "github.com/brian-nunez/baccess/v1"
	"strings"
)

type User struct {
	Roles []string
}

func (u User) GetRoles() []string { return u.Roles }

type Request struct {
	Body string
}

func main() {
	cfgData := map[string]any{
		"policies": map[string]any{
			"moderator": map[string]any{
				"allow": []string{"approve:no_bad_words"},
			},
		},
	}
	cfg, _ := baccess.LoadConfigFromMap(cfgData)

	rbac := baccess.NewRBAC[User, Request]()
	registry := baccess.NewRegistry[User, Request]()

	// Custom Predicate: Check resource content
	noBadWords := func(req baccess.AccessRequest[User, Request]) bool {
		return !strings.Contains(req.Resource.Body, "spam")
	}
	registry.Register("no_bad_words", baccess.Predicate[baccess.AccessRequest[User, Request]](noBadWords))

	evaluator, _ := baccess.BuildEvaluator(cfg, rbac, registry)

	mod := User{Roles: []string{"moderator"}}
	goodReq := Request{Body: "Hello world"}
	badReq := Request{Body: "Buy this spam now"}

	fmt.Printf("Approve good req: %v\n", evaluator.Evaluate(baccess.AccessRequest[User, Request]{Subject: mod, Resource: goodReq, Action: "approve:no_bad_words"}))
	fmt.Printf("Approve bad req:  %v\n", evaluator.Evaluate(baccess.AccessRequest[User, Request]{Subject: mod, Resource: badReq, Action: "approve:no_bad_words"}))
}
