package main

import (
	"brian-nunez/baccess/pkg/auth"
	"brian-nunez/baccess/pkg/config"
	"brian-nunez/baccess/pkg/predicates"
	"fmt"
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
	cfg, _ := config.LoadConfigFromMap(cfgData)

	rbac := auth.NewRBAC[User, Request]()
	registry := auth.NewRegistry[User, Request]()

	// Custom Predicate: Check resource content
	noBadWords := func(req auth.AccessRequest[User, Request]) bool {
		return !strings.Contains(req.Resource.Body, "spam")
	}
	registry.Register("no_bad_words", predicates.Predicate[auth.AccessRequest[User, Request]](noBadWords))

	evaluator, _ := config.BuildEvaluator(cfg, rbac, registry)

	mod := User{Roles: []string{"moderator"}}
	goodReq := Request{Body: "Hello world"}
	badReq := Request{Body: "Buy this spam now"}

	fmt.Printf("Approve good req: %v\n", evaluator.Evaluate(auth.AccessRequest[User, Request]{Subject: mod, Resource: goodReq, Action: "approve"}))
	fmt.Printf("Approve bad req:  %v\n", evaluator.Evaluate(auth.AccessRequest[User, Request]{Subject: mod, Resource: badReq, Action: "approve"}))
}
