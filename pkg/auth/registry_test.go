package auth_test

import (
	"testing"

	"github.com/brian-nunez/baccess/pkg/auth"
	"github.com/brian-nunez/baccess/pkg/predicates"
	"github.com/stretchr/testify/assert"
)

type RegistryTestSubject struct {
	ID string
}

type RegistryTestResource struct {
	ID string
}

func testPredicate[S any, R any](val bool) predicates.Predicate[auth.AccessRequest[S, R]] {
	return func(req auth.AccessRequest[S, R]) bool {
		return val
	}
}

func TestNewRegistry(t *testing.T) {
	reg := auth.NewRegistry[RegistryTestSubject, RegistryTestResource]()
	assert.NotNil(t, reg)
	// Verify that the new registry is empty by trying to get a predicate
	_, err := reg.GetPredicate("anyPredicate")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "predicate not found")
}

func TestRegister(t *testing.T) {
	reg := auth.NewRegistry[RegistryTestSubject, RegistryTestResource]()
	p := testPredicate[RegistryTestSubject, RegistryTestResource](true)

	reg.Register("allow", p)
	// Verify registration by successfully getting the predicate
	foundP, err := reg.GetPredicate("allow")
	assert.NoError(t, err)
	assert.NotNil(t, foundP)

	// Registering same name should overwrite
	reg.Register("allow", testPredicate[RegistryTestSubject, RegistryTestResource](false))
	// Verify overwrite
	overwrittenP, err := reg.GetPredicate("allow")
	assert.NoError(t, err)
	assert.NotNil(t, overwrittenP)
	assert.False(t, overwrittenP.IsSatisfiedBy(auth.AccessRequest[RegistryTestSubject, RegistryTestResource]{}))
}

func TestGetPredicate(t *testing.T) {
	reg := auth.NewRegistry[RegistryTestSubject, RegistryTestResource]()
	trueP := testPredicate[RegistryTestSubject, RegistryTestResource](true)
	falseP := testPredicate[RegistryTestSubject, RegistryTestResource](false)

	reg.Register("truePredicate", trueP)
	reg.Register("falsePredicate", falseP)

	// Test existing predicate
	p, err := reg.GetPredicate("truePredicate")
	assert.NoError(t, err)
	assert.NotNil(t, p)
	assert.True(t, p.IsSatisfiedBy(auth.AccessRequest[RegistryTestSubject, RegistryTestResource]{}))

	p, err = reg.GetPredicate("falsePredicate")
	assert.NoError(t, err)
	assert.NotNil(t, p)
	assert.False(t, p.IsSatisfiedBy(auth.AccessRequest[RegistryTestSubject, RegistryTestResource]{}))

	// Test non-existent predicate
	p, err = reg.GetPredicate("nonExistentPredicate")
	assert.Error(t, err)
	assert.Nil(t, p)
	assert.EqualError(t, err, "predicate not found: nonExistentPredicate")
}
