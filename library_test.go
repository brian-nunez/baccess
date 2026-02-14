package baccess_test

import (
	"testing"

	"github.com/brian-nunez/baccess"
	auth_test_utils "github.com/brian-nunez/baccess/test"
	"github.com/stretchr/testify/assert"
)

func TestAllow(t *testing.T) {
	req := baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{}
	assert.True(t, baccess.Allow[auth_test_utils.MockSubject, auth_test_utils.MockResource]().IsSatisfiedBy(req))
}

func TestDeny(t *testing.T) {
	req := baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{}
	assert.False(t, baccess.Deny[auth_test_utils.MockSubject, auth_test_utils.MockResource]().IsSatisfiedBy(req))
}

func TestIs(t *testing.T) {
	truePredicate := baccess.Predicate[baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]](func(req baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]) bool {
		return true
	})
	falsePredicate := baccess.Predicate[baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]](func(req baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]) bool {
		return false
	})

	req := baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{}

	assert.True(t, baccess.Is[auth_test_utils.MockSubject, auth_test_utils.MockResource](truePredicate).IsSatisfiedBy(req))
	assert.False(t, baccess.Is[auth_test_utils.MockSubject, auth_test_utils.MockResource](falsePredicate).IsSatisfiedBy(req))
}

func TestNot(t *testing.T) {
	truePredicate := baccess.Predicate[baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]](func(req baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]) bool {
		return true
	})
	falsePredicate := baccess.Predicate[baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]](func(req baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]) bool {
		return false
	})

	req := baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{}

	assert.False(t, baccess.Not[auth_test_utils.MockSubject, auth_test_utils.MockResource](truePredicate).IsSatisfiedBy(req))
	assert.True(t, baccess.Not[auth_test_utils.MockSubject, auth_test_utils.MockResource](falsePredicate).IsSatisfiedBy(req))
}

func TestFieldEquals(t *testing.T) {
	subject := auth_test_utils.MockSubject{ID: "user1"}
	resource := auth_test_utils.MockResource{OwnerID: "user1"}
	req := baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{Subject: subject, Resource: resource}

	predicate := baccess.FieldEquals(
		func(s auth_test_utils.MockSubject) string { return s.ID },
		func(r auth_test_utils.MockResource) string { return r.OwnerID },
	)
	assert.True(t, predicate.IsSatisfiedBy(req))

	req.Subject.ID = "user2"
	assert.False(t, predicate.IsSatisfiedBy(req))
}

func TestFieldNotEquals(t *testing.T) {
	subject := auth_test_utils.MockSubject{ID: "user1"}
	resource := auth_test_utils.MockResource{OwnerID: "user2"}
	req := baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{Subject: subject, Resource: resource}

	predicate := baccess.FieldNotEquals(
		func(s auth_test_utils.MockSubject) string { return s.ID },
		func(r auth_test_utils.MockResource) string { return r.OwnerID },
	)
	assert.True(t, predicate.IsSatisfiedBy(req))

	req.Subject.ID = "user2"
	assert.False(t, predicate.IsSatisfiedBy(req))
}

func TestSubjectMatches(t *testing.T) {
	subject := auth_test_utils.MockSubject{Department: "IT"}
	resource := auth_test_utils.MockResource{}
	req := baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{Subject: subject, Resource: resource}

	predicate := baccess.SubjectMatches[auth_test_utils.MockSubject, auth_test_utils.MockResource](
		func(s auth_test_utils.MockSubject) string { return s.Department },
		"IT",
	)
	assert.True(t, predicate.IsSatisfiedBy(req))

	predicate = baccess.SubjectMatches[auth_test_utils.MockSubject, auth_test_utils.MockResource](
		func(s auth_test_utils.MockSubject) string { return s.Department },
		"HR",
	)
	assert.False(t, predicate.IsSatisfiedBy(req))
}

func TestResourceMatches(t *testing.T) {
	subject := auth_test_utils.MockSubject{}
	resource := auth_test_utils.MockResource{Status: "pending"}
	req := baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{Subject: subject, Resource: resource}

	predicate := baccess.ResourceMatches[auth_test_utils.MockSubject, auth_test_utils.MockResource](
		func(r auth_test_utils.MockResource) string { return r.Status },
		"pending",
	)
	assert.True(t, predicate.IsSatisfiedBy(req))

	predicate = baccess.ResourceMatches[auth_test_utils.MockSubject, auth_test_utils.MockResource](
		func(r auth_test_utils.MockResource) string { return r.Status },
		"approved",
	)
	assert.False(t, predicate.IsSatisfiedBy(req))
}

func TestSubjectInResourceList(t *testing.T) {
	subject := auth_test_utils.MockSubject{ID: "user1"}
	resource := auth_test_utils.MockResource{Collaborators: []string{"user1", "user3"}}
	req := baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{Subject: subject, Resource: resource}

	predicate := baccess.SubjectInResourceList(
		func(s auth_test_utils.MockSubject) string { return s.ID },
		func(r auth_test_utils.MockResource) []string { return r.Collaborators },
	)
	assert.True(t, predicate.IsSatisfiedBy(req))

	req.Subject.ID = "user2"
	assert.False(t, predicate.IsSatisfiedBy(req))
}

func TestListIntersection(t *testing.T) {
	subject := auth_test_utils.MockSubject{Tags: []string{"tagA", "tagB"}}
	resource := auth_test_utils.MockResource{Permissions: []string{"tagB", "tagC"}}
	req := baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{Subject: subject, Resource: resource}

	predicate := baccess.ListIntersection(
		func(s auth_test_utils.MockSubject) []string { return s.Tags },
		func(r auth_test_utils.MockResource) []string { return r.Permissions },
	)
	assert.True(t, predicate.IsSatisfiedBy(req))

	req.Subject.Tags = []string{"tagD"}
	assert.False(t, predicate.IsSatisfiedBy(req))

	req.Subject.Tags = []string{}
	req.Resource.Permissions = []string{}
	assert.False(t, predicate.IsSatisfiedBy(req))
}

func TestSubjectAttrEquals(t *testing.T) {
	subject := auth_test_utils.MockSubject{Attributes: map[string]any{"level": 10}}
	resource := auth_test_utils.MockResource{}
	req := baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{Subject: subject, Resource: resource}

	predicate := baccess.SubjectAttrEquals[auth_test_utils.MockSubject, auth_test_utils.MockResource]("level", 10)
	assert.True(t, predicate.IsSatisfiedBy(req))

	predicate = baccess.SubjectAttrEquals[auth_test_utils.MockSubject, auth_test_utils.MockResource]("level", 5)
	assert.False(t, predicate.IsSatisfiedBy(req))

	predicate = baccess.SubjectAttrEquals[auth_test_utils.MockSubject, auth_test_utils.MockResource]("nonexistent", nil)
	assert.True(t, predicate.IsSatisfiedBy(req)) // Should be true if the attribute is not set and we're checking for nil

	subject2 := auth_test_utils.MockSubject{Attributes: map[string]any{"active": true}}
	req2 := baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{Subject: subject2, Resource: resource}
	predicate = baccess.SubjectAttrEquals[auth_test_utils.MockSubject, auth_test_utils.MockResource]("active", true)
	assert.True(t, predicate.IsSatisfiedBy(req2))
}

func TestSubjectAttrGT(t *testing.T) {
	subject := auth_test_utils.MockSubject{Attributes: map[string]any{"age": 30}}
	resource := auth_test_utils.MockResource{}
	req := baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{Subject: subject, Resource: resource}

	predicate := baccess.SubjectAttrGT[auth_test_utils.MockSubject, auth_test_utils.MockResource]("age", 25)
	assert.True(t, predicate.IsSatisfiedBy(req))

	predicate = baccess.SubjectAttrGT[auth_test_utils.MockSubject, auth_test_utils.MockResource]("age", 30)
	assert.False(t, predicate.IsSatisfiedBy(req))

	predicate = baccess.SubjectAttrGT[auth_test_utils.MockSubject, auth_test_utils.MockResource]("age", 35)
	assert.False(t, predicate.IsSatisfiedBy(req))

	predicate = baccess.SubjectAttrGT[auth_test_utils.MockSubject, auth_test_utils.MockResource]("nonexistent", 0)
	assert.False(t, predicate.IsSatisfiedBy(req)) // non-existent attribute should not be greater
}

func TestSubjectAttrLT(t *testing.T) {
	subject := auth_test_utils.MockSubject{Attributes: map[string]any{"age": 30}}
	resource := auth_test_utils.MockResource{}
	req := baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{Subject: subject, Resource: resource}

	predicate := baccess.SubjectAttrLT[auth_test_utils.MockSubject, auth_test_utils.MockResource]("age", 35)
	assert.True(t, predicate.IsSatisfiedBy(req))

	predicate = baccess.SubjectAttrLT[auth_test_utils.MockSubject, auth_test_utils.MockResource]("age", 30)
	assert.False(t, predicate.IsSatisfiedBy(req))

	predicate = baccess.SubjectAttrLT[auth_test_utils.MockSubject, auth_test_utils.MockResource]("age", 25)
	assert.False(t, predicate.IsSatisfiedBy(req))

	predicate = baccess.SubjectAttrLT[auth_test_utils.MockSubject, auth_test_utils.MockResource]("nonexistent", 100)
	assert.False(t, predicate.IsSatisfiedBy(req)) // non-existent attribute should not be less
}

func TestSubjectAttrTrue(t *testing.T) {
	subject := auth_test_utils.MockSubject{Attributes: map[string]any{"isActive": true, "isAdmin": false, "name": "test"}}
	resource := auth_test_utils.MockResource{}
	req := baccess.AccessRequest[auth_test_utils.MockSubject, auth_test_utils.MockResource]{Subject: subject, Resource: resource}

	predicate := baccess.SubjectAttrTrue[auth_test_utils.MockSubject, auth_test_utils.MockResource]("isActive")
	assert.True(t, predicate.IsSatisfiedBy(req))

	predicate = baccess.SubjectAttrTrue[auth_test_utils.MockSubject, auth_test_utils.MockResource]("isAdmin")
	assert.False(t, predicate.IsSatisfiedBy(req))

	predicate = baccess.SubjectAttrTrue[auth_test_utils.MockSubject, auth_test_utils.MockResource]("nonexistent")
	assert.False(t, predicate.IsSatisfiedBy(req))

	predicate = baccess.SubjectAttrTrue[auth_test_utils.MockSubject, auth_test_utils.MockResource]("name") // string is not bool
	assert.False(t, predicate.IsSatisfiedBy(req))
}
