package baccess_test

import (
	"testing"

	"github.com/brian-nunez/baccess"
	"github.com/stretchr/testify/assert"
)

type testUser struct {
	ID    string
	Roles []string
	Attrs map[string]any
}

func (u testUser) GetRoles() []string { return u.Roles }
func (u testUser) GetAttribute(key string) any {
	return u.Attrs[key]
}

type testDoc struct {
	OwnerID string
}

func TestFacadePolicyFlow(t *testing.T) {
	cfgData := map[string]any{
		"policies": map[string]any{
			"editor": map[string]any{
				"allow": []string{"edit:isOwner"},
			},
		},
	}

	cfg, err := baccess.LoadConfigFromMap(cfgData)
	assert.NoError(t, err)

	rbac := baccess.NewRBAC[testUser, testDoc]()
	registry := baccess.NewRegistry[testUser, testDoc]()
	registry.Register("isOwner", baccess.FieldEquals(
		func(u testUser) string { return u.ID },
		func(d testDoc) string { return d.OwnerID },
	))

	evaluator, err := baccess.BuildEvaluator(cfg, rbac, registry)
	assert.NoError(t, err)

	ownerReq := baccess.AccessRequest[testUser, testDoc]{
		Subject:  testUser{ID: "alice", Roles: []string{"editor"}},
		Resource: testDoc{OwnerID: "alice"},
		Action:   "edit:isOwner",
	}
	nonOwnerReq := baccess.AccessRequest[testUser, testDoc]{
		Subject:  testUser{ID: "bob", Roles: []string{"editor"}},
		Resource: testDoc{OwnerID: "alice"},
		Action:   "edit:isOwner",
	}

	assert.True(t, evaluator.Evaluate(ownerReq))
	assert.False(t, evaluator.Evaluate(nonOwnerReq))
}

func TestFacadePredicateAliasMethods(t *testing.T) {
	isEven := baccess.Predicate[int](func(v int) bool { return v%2 == 0 })
	isPositive := baccess.Predicate[int](func(v int) bool { return v > 0 })

	combined := isEven.And(isPositive)

	assert.True(t, combined.IsSatisfiedBy(2))
	assert.False(t, combined.IsSatisfiedBy(-2))
}
