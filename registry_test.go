package baccess_test

import (
	"testing"

	baccess "github.com/brian-nunez/baccess/v1"
	"github.com/stretchr/testify/assert"
)

type RegistryTestSubject struct {
	ID string
}

type RegistryTestResource struct {
	ID string
}

func testPredicate[S any, R any](val bool) baccess.Predicate[baccess.AccessRequest[S, R]] {
	return func(req baccess.AccessRequest[S, R]) bool {
		return val
	}
}

func TestNewRegistry(t *testing.T) {
	reg := baccess.NewRegistry[RegistryTestSubject, RegistryTestResource]()
	assert.NotNil(t, reg)
	// Verify that the new registry is empty by trying to get a predicate
	_, err := reg.GetPredicate("anyPredicate")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "predicate not found")
}

func TestRegister(t *testing.T) {
	reg := baccess.NewRegistry[RegistryTestSubject, RegistryTestResource]()
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
	assert.False(t, overwrittenP.IsSatisfiedBy(baccess.AccessRequest[RegistryTestSubject, RegistryTestResource]{}))
}

func TestGetPredicate(t *testing.T) {
	reg := baccess.NewRegistry[RegistryTestSubject, RegistryTestResource]()
	trueP := testPredicate[RegistryTestSubject, RegistryTestResource](true)
	falseP := testPredicate[RegistryTestSubject, RegistryTestResource](false)

	reg.Register("truePredicate", trueP)
	reg.Register("falsePredicate", falseP)

	// Test existing predicate
	p, err := reg.GetPredicate("truePredicate")
	assert.NoError(t, err)
	assert.NotNil(t, p)
	assert.True(t, p.IsSatisfiedBy(baccess.AccessRequest[RegistryTestSubject, RegistryTestResource]{}))

	p, err = reg.GetPredicate("falsePredicate")
	assert.NoError(t, err)
	assert.NotNil(t, p)
	assert.False(t, p.IsSatisfiedBy(baccess.AccessRequest[RegistryTestSubject, RegistryTestResource]{}))

	// Test non-existent predicate
	p, err = reg.GetPredicate("nonExistentPredicate")
	assert.Error(t, err)
	assert.Nil(t, p)
	assert.EqualError(t, err, "predicate not found: nonExistentPredicate")
}
