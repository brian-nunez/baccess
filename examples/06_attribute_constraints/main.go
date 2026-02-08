package main

import (
	"brian-nunez/baccess/pkg/auth"
	"brian-nunez/baccess/pkg/config"
	"fmt"
)

type User struct {
	Roles []string
	Attrs map[string]any
}

func (u User) GetRoles() []string          { return u.Roles }
func (u User) GetAttribute(key string) any { return u.Attrs[key] }

type Area struct{}

func main() {
	cfgData := map[string]any{
		"policies": map[string]any{
			"player": map[string]any{
				"allow": []string{
					"enter_vip:level_above_10",
				},
			},
		},
	}
	cfg, _ := config.LoadConfigFromMap(cfgData)

	rbac := auth.NewRBAC[User, Area]()
	registry := auth.NewRegistry[User, Area]()

	// Register generic attribute check
	registry.Register("level_above_10", auth.SubjectAttrGT[User, Area]("level", 10))

	evaluator, _ := config.BuildEvaluator(cfg, rbac, registry)

	newbie := User{Roles: []string{"player"}, Attrs: map[string]any{"level": 5}}
	pro := User{Roles: []string{"player"}, Attrs: map[string]any{"level": 20}}
	area := Area{}

	fmt.Printf("Newbie enter VIP: %v\n", evaluator.Evaluate(auth.AccessRequest[User, Area]{Subject: newbie, Resource: area, Action: "enter_vip"}))
	fmt.Printf("Pro enter VIP:    %v\n", evaluator.Evaluate(auth.AccessRequest[User, Area]{Subject: pro, Resource: area, Action: "enter_vip"}))
}
