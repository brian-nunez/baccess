package auth_test

import (
	"testing"

	"github.com/brian-nunez/baccess/pkg/auth"
	auth_test_utils "github.com/brian-nunez/baccess/pkg/auth/test"
	"github.com/stretchr/testify/assert"
)

func TestAccessRequest(t *testing.T) {
	subject := "testUser"
	resource := "testResource"
	action := "read"

	req := auth.AccessRequest[string, string]{
		Subject:  subject,
		Resource: resource,
		Action:   action,
	}

	assert.Equal(t, subject, req.Subject)
	assert.Equal(t, resource, req.Resource)
	assert.Equal(t, action, req.Action)
}

func TestRoleBearer(t *testing.T) {
	roles := []string{"admin", "editor"}
	rb := auth_test_utils.MockRoleBearer{Roles: roles}

	assert.Equal(t, roles, rb.GetRoles())
	assert.Contains(t, rb.GetRoles(), "admin")
	assert.NotContains(t, rb.GetRoles(), "viewer")
}

func TestIdentifiable(t *testing.T) {
	id := 123
	ident := auth_test_utils.MockIdentifiable{ID: id}

	assert.Equal(t, id, ident.GetID())

	idString := "user-abc"
	identString := auth_test_utils.MockIdentifiable{ID: idString}
	assert.Equal(t, idString, identString.GetID())
}

func TestAttributable(t *testing.T) {
	attributes := map[string]any{
		"department": "IT",
		"clearance":  5,
	}
	attr := auth_test_utils.MockAttributable{Attributes: attributes}

	assert.Equal(t, "IT", attr.GetAttribute("department"))
	assert.Equal(t, 5, attr.GetAttribute("clearance"))
	assert.Nil(t, attr.GetAttribute("nonexistent"))

	resourceAttributes := map[string]any{
		"status":  "active",
		"version": 2,
	}
	mockResource := auth_test_utils.MockResource{Attributes: resourceAttributes}
	assert.Equal(t, "active", mockResource.GetAttribute("status"))
	assert.Equal(t, 2, mockResource.GetAttribute("version"))
	assert.Nil(t, mockResource.GetAttribute("nonexistent_attribute"))
}
