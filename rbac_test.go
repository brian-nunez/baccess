package baccess_test

import (
	"testing"

	baccess "github.com/brian-nunez/baccess/v1"
	auth_test_utils "github.com/brian-nunez/baccess/v1/test"
	"github.com/stretchr/testify/assert"
)

func TestHasRole(t *testing.T) {
	adminUser := auth_test_utils.MockRoleBearer{Roles: []string{"admin", "user"}}
	user := auth_test_utils.MockRoleBearer{Roles: []string{"user"}}
	guestUser := auth_test_utils.MockRoleBearer{Roles: []string{"guest"}}
	resource := auth_test_utils.MockResource{ID: "doc1"}

	testCases := []struct {
		name     string
		subject  auth_test_utils.MockRoleBearer
		role     string
		expected bool
	}{
		{
			name:     "admin user has admin role",
			subject:  adminUser,
			role:     "admin",
			expected: true,
		},
		{
			name:     "admin user has user role",
			subject:  adminUser,
			role:     "user",
			expected: true,
		},
		{
			name:     "user does not have admin role",
			subject:  user,
			role:     "admin",
			expected: false,
		},
		{
			name:     "guest user has guest role",
			subject:  guestUser,
			role:     "guest",
			expected: true,
		},
		{
			name:     "guest user does not have non-existent role",
			subject:  guestUser,
			role:     "non-existent",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := baccess.AccessRequest[auth_test_utils.MockRoleBearer, auth_test_utils.MockResource]{
				Subject:  tc.subject,
				Resource: resource,
				Action:   "read", // Action doesn't matter for HasRole
			}
			predicate := baccess.HasRole[auth_test_utils.MockRoleBearer, auth_test_utils.MockResource](tc.role)
			assert.Equal(t, tc.expected, predicate.IsSatisfiedBy(req))
		})
	}
}

func TestHasAnyRole(t *testing.T) {
	adminUser := auth_test_utils.MockRoleBearer{Roles: []string{"admin", "user"}}
	editorUser := auth_test_utils.MockRoleBearer{Roles: []string{"editor", "user"}}
	user := auth_test_utils.MockRoleBearer{Roles: []string{"user"}}
	guestUser := auth_test_utils.MockRoleBearer{Roles: []string{"guest"}}
	resource := auth_test_utils.MockResource{ID: "doc1"}

	testCases := []struct {
		name        string
		subject     auth_test_utils.MockRoleBearer
		targetRoles []string
		expected    bool
	}{
		{
			name:        "admin user has admin or editor role (admin)",
			subject:     adminUser,
			targetRoles: []string{"admin", "editor"},
			expected:    true,
		},
		{
			name:        "editor user has admin or editor role (editor)",
			subject:     editorUser,
			targetRoles: []string{"admin", "editor"},
			expected:    true,
		},
		{
			name:        "user has admin or editor role (neither)",
			subject:     user,
			targetRoles: []string{"admin", "editor"},
			expected:    false,
		},
		{
			name:        "user has user role",
			subject:     user,
			targetRoles: []string{"user"},
			expected:    true,
		},
		{
			name:        "guest user has admin or editor role (none)",
			subject:     guestUser,
			targetRoles: []string{"admin", "editor"},
			expected:    false,
		},
		{
			name:        "guest user has guest role",
			subject:     guestUser,
			targetRoles: []string{"guest"},
			expected:    true,
		},
		{
			name:        "empty target roles",
			subject:     adminUser,
			targetRoles: []string{},
			expected:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := baccess.AccessRequest[auth_test_utils.MockRoleBearer, auth_test_utils.MockResource]{
				Subject:  tc.subject,
				Resource: resource,
				Action:   "write", // Action doesn't matter for HasAnyRole
			}
			predicate := baccess.HasAnyRole[auth_test_utils.MockRoleBearer, auth_test_utils.MockResource](tc.targetRoles...)
			assert.Equal(t, tc.expected, predicate.IsSatisfiedBy(req))
		})
	}
}

func TestRBAC_HasRole(t *testing.T) {
	rbac := baccess.NewRBAC[auth_test_utils.MockRoleBearer, auth_test_utils.MockResource]()
	adminUser := auth_test_utils.MockRoleBearer{Roles: []string{"admin", "user"}}
	resource := auth_test_utils.MockResource{ID: "doc1"} // Use MockResource from test_utils.go

	req := baccess.AccessRequest[auth_test_utils.MockRoleBearer, auth_test_utils.MockResource]{
		Subject:  adminUser,
		Resource: resource,
		Action:   "read",
	}

	predicate := rbac.HasRole("admin")
	assert.True(t, predicate.IsSatisfiedBy(req))

	predicate = rbac.HasRole("editor")
	assert.False(t, predicate.IsSatisfiedBy(req))
}

func TestRBAC_HasAnyRole(t *testing.T) {
	rbac := baccess.NewRBAC[auth_test_utils.MockRoleBearer, auth_test_utils.MockResource]()
	editorUser := auth_test_utils.MockRoleBearer{Roles: []string{"editor", "user"}}
	resource := auth_test_utils.MockResource{ID: "doc1"} // Use MockResource from test_utils.go

	req := baccess.AccessRequest[auth_test_utils.MockRoleBearer, auth_test_utils.MockResource]{
		Subject:  editorUser,
		Resource: resource,
		Action:   "edit",
	}

	predicate := rbac.HasAnyRole("admin", "editor")
	assert.True(t, predicate.IsSatisfiedBy(req))

	predicate = rbac.HasAnyRole("admin", "guest")
	assert.False(t, predicate.IsSatisfiedBy(req))

	predicate = rbac.HasAnyRole("user")
	assert.True(t, predicate.IsSatisfiedBy(req))
}
