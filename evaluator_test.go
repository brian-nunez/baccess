package baccess_test

import (
	"testing"

	baccess "github.com/brian-nunez/baccess/v1"
	auth_test_utils "github.com/brian-nunez/baccess/v1/test"
	"github.com/stretchr/testify/assert"
)

func alwaysTrue[S any, R any]() baccess.Predicate[baccess.AccessRequest[S, R]] {
	return func(req baccess.AccessRequest[S, R]) bool { return true }
}

func alwaysFalse[S any, R any]() baccess.Predicate[baccess.AccessRequest[S, R]] {
	return func(req baccess.AccessRequest[S, R]) bool { return false }
}

func isOwner() baccess.Predicate[baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]] {
	return func(req baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]) bool {
		return req.Subject.ID == req.Resource.OwnerID
	}
}

func isAdmin() baccess.Predicate[baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]] {
	return func(req baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]) bool {
		return req.Subject.ID == "admin"
	}
}

func isDraft() baccess.Predicate[baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]] {
	return func(req baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]) bool {
		return req.Resource.Status == "draft"
	}
}

func TestNewEvaluator(t *testing.T) {
	evaluator := baccess.NewEvaluator[auth_test_utils.MockSubject, auth_test_utils.MockResource]()
	assert.NotNil(t, evaluator)
	// Cannot assert on evaluator.policies directly as it's unexported.
	// Instead, we can verify its state indirectly through Evaluate calls.
	// A new evaluator should deny all access by default.
	req := baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{
		Subject:  auth_test_utils.MockSubject{},
		Resource: auth_test_utils.MockResource{},
		Action:   "any",
	}
	assert.False(t, evaluator.Evaluate(req))
}

func TestAddPolicy(t *testing.T) {
	evaluator := baccess.NewEvaluator[auth_test_utils.MockSubject, auth_test_utils.MockResource]()
	subject := auth_test_utils.MockSubject{ID: "test"}
	resource := auth_test_utils.MockResource{ID: "test"}

	evaluator.AddPolicy("read", alwaysTrue[auth_test_utils.MockSubject, auth_test_utils.MockResource]())
	assert.True(t, evaluator.Evaluate(baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{Subject: subject, Resource: resource, Action: "read"}))
	assert.False(t, evaluator.Evaluate(baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{Subject: subject, Resource: resource, Action: "write"}))

	evaluator.AddPolicy("read", alwaysFalse[auth_test_utils.MockSubject, auth_test_utils.MockResource]())
	assert.True(t, evaluator.Evaluate(baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{Subject: subject, Resource: resource, Action: "read"}))

	evaluator.AddPolicy("write", alwaysTrue[auth_test_utils.MockSubject, auth_test_utils.MockResource]())
	assert.True(t, evaluator.Evaluate(baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{Subject: subject, Resource: resource, Action: "write"}))
}

func TestEvaluator_Evaluate(t *testing.T) {
	evaluator := baccess.NewEvaluator[auth_test_utils.MockSubject, auth_test_utils.MockResource]()
	adminSubject := auth_test_utils.MockSubject{ID: "admin"}
	ownerSubject := auth_test_utils.MockSubject{ID: "user1"}
	otherSubject := auth_test_utils.MockSubject{ID: "user2"}
	doc1 := auth_test_utils.MockResource{OwnerID: "user1", Status: "published"}
	doc2 := auth_test_utils.MockResource{OwnerID: "user2", Status: "draft"}

	// Policies:
	// "read": alwaysTrue (anyone can read)
	// "delete:isOwner": isOwner (only owner can delete)
	// "*": isAdmin (admins can do anything)
	// "update:*": isDraft (can update anything if it's a draft)

	evaluator.AddPolicy("read", alwaysTrue[auth_test_utils.MockSubject, auth_test_utils.MockResource]())
	evaluator.AddPolicy("delete:isOwner", isOwner())
	evaluator.AddPolicy("*", isAdmin())
	evaluator.AddPolicy("update:*", isDraft())

	testCases := []struct {
		name     string
		subject  auth_test_utils.MockSubject
		resource auth_test_utils.MockResource
		action   string
		expected bool
	}{
		// Test "read" action (alwaysTrue)
		{
			name:     "read: any user, any resource -> true",
			subject:  ownerSubject,
			resource: doc1,
			action:   "read",
			expected: true,
		},
		// Test "delete:isOwner"
		{
			name:     "delete: owner can delete",
			subject:  ownerSubject,
			resource: doc1,
			action:   "delete:isOwner",
			expected: true,
		},
		{
			name:     "delete: non-owner cannot delete",
			subject:  otherSubject,
			resource: doc1,
			action:   "delete:isOwner",
			expected: false,
		},
		{
			name:     "delete: admin can delete (due to wildcard)",
			subject:  adminSubject,
			resource: doc1,
			action:   "delete:isOwner",
			expected: true,
		},
		// Test "*" wildcard for admin
		{
			name:     "admin can perform any action",
			subject:  adminSubject,
			resource: doc1,
			action:   "some:action",
			expected: true,
		},
		{
			name:     "admin can perform another action",
			subject:  adminSubject,
			resource: doc2,
			action:   "arbitrary",
			expected: true,
		},
		// Test "update:*" wildcard
		{
			name:     "update: draft resource by non-owner",
			subject:  ownerSubject,
			resource: doc2, // owner is user2, but doc2 is draft
			action:   "update:title",
			expected: true,
		},
		{
			name:     "update: published resource by non-owner -> false",
			subject:  ownerSubject,
			resource: doc1, // doc1 is published
			action:   "update:content",
			expected: false,
		},
		{
			name:     "update: no matching policy",
			subject:  ownerSubject,
			resource: doc1,
			action:   "update", // No condition
			expected: false,
		},
		// Test no matching policy
		{
			name:     "no matching policy for non-admin",
			subject:  ownerSubject,
			resource: doc1,
			action:   "archive",
			expected: false,
		},
		{
			name:     "no matching policy (action without condition, policy with condition)",
			subject:  ownerSubject,
			resource: doc1,
			action:   "delete", // Policy is "delete:isOwner"
			expected: false,
		},
		// Test combined policies
		{
			name:     "combined policies - action 'read' with condition 'something' (admin is true)",
			subject:  adminSubject,
			resource: doc1,
			action:   "read:something",
			expected: true, // admin wildcard
		},
		{
			name:     "combined policies - action 'read' with condition 'something' (alwaysTrue is true)",
			subject:  ownerSubject,
			resource: doc1,
			action:   "read:something",
			expected: true, // "read" policy is alwaysTrue
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{
				Subject:  tc.subject,
				Resource: tc.resource,
				Action:   tc.action,
			}
			actual := evaluator.Evaluate(req)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
