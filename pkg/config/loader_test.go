package config_test

import (
	"errors"
	"os"
	"testing"

	"github.com/brian-nunez/baccess/pkg/auth"
	auth_test_utils "github.com/brian-nunez/baccess/pkg/auth/test"
	"github.com/brian-nunez/baccess/pkg/config"
	"github.com/brian-nunez/baccess/pkg/predicates"
	"github.com/stretchr/testify/assert"
)

type MockPredicateProvider struct {
	Predicates map[string]predicates.Predicate[auth.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]]
}

func (m *MockPredicateProvider) GetPredicate(name string) (predicates.Predicate[auth.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]], error) {
	if p, ok := m.Predicates[name]; ok {
		return p, nil
	}
	return nil, errors.New("predicate not found")
}

func alwaysTrue[S any, R any](req auth.AccessRequest[S, R]) bool  { return true }
func alwaysFalse[S any, R any](req auth.AccessRequest[S, R]) bool { return false }

func TestLoadConfigFromFile(t *testing.T) {
	// Valid config file
	tempFile, err := os.CreateTemp("", "config_*.json")
	assert.NoError(t, err)
	defer os.Remove(tempFile.Name())
	tempFile.WriteString(`{"policies":{"admin":{"allow":["*"]},"editor":{"allow":["read","delete:isOwner"]}}}`)
	tempFile.Close()

	cfg, err := config.LoadConfigFromFile(tempFile.Name())
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Len(t, cfg.Policies, 2)
	assert.Contains(t, cfg.Policies, "admin")
	assert.Contains(t, cfg.Policies, "editor")
	assert.Equal(t, []string{"*"}, cfg.Policies["admin"].Allow)

	cfg, err = config.LoadConfigFromFile("non_existent_file.json")
	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "failed to read config file")
	assert.ErrorContains(t, err, "failed to read config file") // Ensure error message is explicitly matched

	invalidJsonFile, err := os.CreateTemp("", "invalid_config_*.json")
	assert.NoError(t, err)
	defer os.Remove(invalidJsonFile.Name())
	invalidJsonFile.WriteString(`{"policies": "invalid"}`)
	invalidJsonFile.Close()

	cfg, err = config.LoadConfigFromFile(invalidJsonFile.Name())
	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "failed to parse config JSON")
	assert.ErrorContains(t, err, "failed to parse config JSON") // Ensure error message is explicitly matched
}

func TestLoadConfigFromMap(t *testing.T) {
	validMap := map[string]any{
		"policies": map[string]any{
			"admin": map[string]any{
				"allow": []string{"*"},
			},
		},
	}
	cfg, err := config.LoadConfigFromMap(validMap)
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Len(t, cfg.Policies, 1)
	assert.Contains(t, cfg.Policies, "admin")

	invalidMap := map[string]any{
		"policies": map[string]any{
			"editor": map[string]any{
				"allow": "read", // Should be []string
			},
		},
	}
	cfg, err = config.LoadConfigFromMap(invalidMap)
	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "failed to parse config JSON")
	assert.ErrorContains(t, err, "failed to parse config JSON")

	unmarshableMap := map[string]any{
		"policies": map[string]any{
			"admin": map[string]any{
				"allow": func() {}, // Functions cannot be marshalled to JSON
			},
		},
	}
	cfg, err = config.LoadConfigFromMap(unmarshableMap)
	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "failed to marshal config data")
	assert.ErrorContains(t, err, "failed to marshal config data")
}

func TestBuildEvaluator(t *testing.T) {
	rbac := auth.NewRBAC[auth_test_utils.MockSubject, auth_test_utils.MockResource]()
	provider := &MockPredicateProvider{ // Use updated MockPredicateProvider
		Predicates: map[string]predicates.Predicate[auth.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]]{
			"isOwner": func(req auth.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]) bool {
				return req.Subject.GetID() == req.Resource.GetID() // Use GetID() from Identifiable
			},
			"canEdit": func(req auth.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]) bool {
				return true
			},
		},
	}

	config1 := &config.Config{
		Policies: map[string]config.RolePolicyConfig{
			"admin": {Allow: []string{"*"}},
			"user":  {Allow: []string{"read", "edit:canEdit", "delete:isOwner"}},
		},
	}

	evaluator1, err := config.BuildEvaluator[auth_test_utils.MockSubject, auth_test_utils.MockResource](config1, rbac, provider)
	assert.NoError(t, err)
	assert.NotNil(t, evaluator1)

	adminReq := auth.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{
		Subject:  auth_test_utils.MockSubject{ID: "admin", Roles: []string{"admin"}},
		Resource: auth_test_utils.MockResource{ID: "doc1"},
		Action:   "any:action",
	}
	assert.True(t, evaluator1.Evaluate(adminReq))

	// Test user read access
	userReq := auth.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{
		Subject:  auth_test_utils.MockSubject{ID: "user1", Roles: []string{"user"}},
		Resource: auth_test_utils.MockResource{ID: "doc1"},
		Action:   "read",
	}
	assert.True(t, evaluator1.Evaluate(userReq))

	// Test user edit access with condition
	userEditReq := auth.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{
		Subject:  auth_test_utils.MockSubject{ID: "user1", Roles: []string{"user"}},
		Resource: auth_test_utils.MockResource{ID: "doc1"},
		Action:   "edit:canEdit",
	}
	assert.True(t, evaluator1.Evaluate(userEditReq))

	// Test user delete access with condition (isOwner)
	userOwnerDeleteReq := auth.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{
		Subject:  auth_test_utils.MockSubject{ID: "user1", Roles: []string{"user"}},
		Resource: auth_test_utils.MockResource{ID: "user1"}, // Subject is owner
		Action:   "delete:isOwner",
	}
	assert.True(t, evaluator1.Evaluate(userOwnerDeleteReq))

	userNonOwnerDeleteReq := auth.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{
		Subject:  auth_test_utils.MockSubject{ID: "user2", Roles: []string{"user"}},
		Resource: auth_test_utils.MockResource{ID: "user1"}, // Subject is NOT owner
		Action:   "delete:isOwner",
	}
	assert.False(t, evaluator1.Evaluate(userNonOwnerDeleteReq))

	config2 := &config.Config{
		Policies: map[string]config.RolePolicyConfig{
			"guest": {Allow: []string{"view:nonExistentPredicate"}},
		},
	}
	evaluator2, err := config.BuildEvaluator[auth_test_utils.MockSubject, auth_test_utils.MockResource](config2, rbac, provider)
	assert.Error(t, err) // Expect an error about missing predicate
	assert.NotNil(t, evaluator2)

	// Even with an error, the evaluator should still deny access if predicate is missing
	guestReq := auth.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{
		Subject:  auth_test_utils.MockSubject{ID: "guest", Roles: []string{"guest"}},
		Resource: auth_test_utils.MockResource{ID: "publicDoc"},
		Action:   "view:nonExistentPredicate",
	}
	assert.False(t, evaluator2.Evaluate(guestReq))

	// Policy with action wildcard, condition specified by user, policy matches action part of req
	config3 := &config.Config{
		Policies: map[string]config.RolePolicyConfig{
			"dev": {Allow: []string{"deploy:staging"}}, // Explicit action and condition
		},
	}
	provider3 := &MockPredicateProvider{
		Predicates: map[string]predicates.Predicate[auth.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]]{
			"staging": func(req auth.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]) bool {
				return req.Action == "deploy:staging" // Predicate checks the full action string
			},
		},
	}
	evaluator3, err := config.BuildEvaluator[auth_test_utils.MockSubject, auth_test_utils.MockResource](config3, rbac, provider3)
	assert.NoError(t, err)

	devReq := auth.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{
		Subject:  auth_test_utils.MockSubject{ID: "dev1", Roles: []string{"dev"}},
		Resource: auth_test_utils.MockResource{ID: "app1"},
		Action:   "deploy:staging",
	}
	assert.True(t, evaluator3.Evaluate(devReq))

	devReqWrongCondition := auth.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{
		Subject:  auth_test_utils.MockSubject{ID: "dev1", Roles: []string{"dev"}},
		Resource: auth_test_utils.MockResource{ID: "app1"},
		Action:   "deploy:production",
	}
	assert.False(t, evaluator3.Evaluate(devReqWrongCondition))

	// policyKey condition is "*"
	config4 := &config.Config{
		Policies: map[string]config.RolePolicyConfig{
			"viewer": {Allow: []string{"view:*"}},
		},
	}
	evaluator4, err := config.BuildEvaluator[auth_test_utils.MockSubject, auth_test_utils.MockResource](config4, rbac, provider)
	assert.NoError(t, err)

	viewerReq := auth.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{
		Subject:  auth_test_utils.MockSubject{ID: "viewer1", Roles: []string{"viewer"}},
		Resource: auth_test_utils.MockResource{ID: "data"},
		Action:   "view:some_sub_action",
	}
	assert.True(t, evaluator4.Evaluate(viewerReq))

	viewerReqNoCondition := auth.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{
		Subject:  auth_test_utils.MockSubject{ID: "viewer1", Roles: []string{"viewer"}},
		Resource: auth_test_utils.MockResource{ID: "data"},
		Action:   "view",
	}
	assert.True(t, evaluator4.Evaluate(viewerReqNoCondition))

	viewerReqWrongAction := auth.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{
		Subject:  auth_test_utils.MockSubject{ID: "viewer1", Roles: []string{"viewer"}},
		Resource: auth_test_utils.MockResource{ID: "data"},
		Action:   "edit:some_sub_action",
	}
	assert.False(t, evaluator4.Evaluate(viewerReqWrongAction))

	// "action" rule without explicit condition in config, treated as "action:*" (implicitly always true)
	config5 := &config.Config{
		Policies: map[string]config.RolePolicyConfig{
			"printer": {Allow: []string{"print"}},
		},
	}
	evaluator5, err := config.BuildEvaluator[auth_test_utils.MockSubject, auth_test_utils.MockResource](config5, rbac, provider)
	assert.NoError(t, err)

	printerReq := auth.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{
		Subject:  auth_test_utils.MockSubject{ID: "printer1", Roles: []string{"printer"}},
		Resource: auth_test_utils.MockResource{ID: "document"},
		Action:   "print",
	}
	assert.True(t, evaluator5.Evaluate(printerReq))

	printerReqWithCondition := auth.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{
		Subject:  auth_test_utils.MockSubject{ID: "printer1", Roles: []string{"printer"}},
		Resource: auth_test_utils.MockResource{ID: "document"},
		Action:   "print:draft",
	}
	assert.True(t, evaluator5.Evaluate(printerReqWithCondition))

	printerReqWrongAction := auth.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{
		Subject:  auth_test_utils.MockSubject{ID: "printer1", Roles: []string{"printer"}},
		Resource: auth_test_utils.MockResource{ID: "document"},
		Action:   "scan",
	}
	assert.False(t, evaluator5.Evaluate(printerReqWrongAction))
}
