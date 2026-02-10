package baccess_test

import (
	"testing"

	baccess "github.com/brian-nunez/baccess/v1"
	"github.com/stretchr/testify/assert"
)

func TestPredicate_IsSatisfiedBy(t *testing.T) {
	testCases := []struct {
		name      string
		predicate baccess.Predicate[int]
		entity    int
		expected  bool
	}{
		{
			name:      "true predicate",
			predicate: func(i int) bool { return true },
			entity:    1,
			expected:  true,
		},
		{
			name:      "false predicate",
			predicate: func(i int) bool { return false },
			entity:    1,
			expected:  false,
		},
		{
			name:      "check equality",
			predicate: func(i int) bool { return i == 10 },
			entity:    10,
			expected:  true,
		},
		{
			name:      "check inequality",
			predicate: func(i int) bool { return i == 10 },
			entity:    5,
			expected:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.predicate.IsSatisfiedBy(tc.entity)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestPredicate_And(t *testing.T) {
	alwaysTrue := baccess.Predicate[int](func(i int) bool { return true })
	alwaysFalse := baccess.Predicate[int](func(i int) bool { return false })
	isTen := baccess.Predicate[int](func(i int) bool { return i == 10 })

	testCases := []struct {
		name      string
		predicate baccess.Predicate[int]
		other     baccess.Predicate[int]
		entity    int
		expected  bool
	}{
		{
			name:      "true AND true",
			predicate: alwaysTrue,
			other:     alwaysTrue,
			entity:    1,
			expected:  true,
		},
		{
			name:      "true AND false",
			predicate: alwaysTrue,
			other:     alwaysFalse,
			entity:    1,
			expected:  false,
		},
		{
			name:      "false AND true",
			predicate: alwaysFalse,
			other:     alwaysTrue,
			entity:    1,
			expected:  false,
		},
		{
			name:      "false AND false",
			predicate: alwaysFalse,
			other:     alwaysFalse,
			entity:    1,
			expected:  false,
		},
		{
			name:      "isTen AND true (entity 10)",
			predicate: isTen,
			other:     alwaysTrue,
			entity:    10,
			expected:  true,
		},
		{
			name:      "isTen AND true (entity 5)",
			predicate: isTen,
			other:     alwaysTrue,
			entity:    5,
			expected:  false,
		},
		{
			name:      "true AND isTen (entity 10)",
			predicate: alwaysTrue,
			other:     isTen,
			entity:    10,
			expected:  true,
		},
		{
			name:      "true AND isTen (entity 5)",
			predicate: alwaysTrue,
			other:     isTen,
			entity:    5,
			expected:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			combined := tc.predicate.And(tc.other)
			actual := combined.IsSatisfiedBy(tc.entity)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestPredicate_Or(t *testing.T) {
	alwaysTrue := baccess.Predicate[int](func(i int) bool { return true })
	alwaysFalse := baccess.Predicate[int](func(i int) bool { return false })
	isTen := baccess.Predicate[int](func(i int) bool { return i == 10 })

	testCases := []struct {
		name      string
		predicate baccess.Predicate[int]
		other     baccess.Predicate[int]
		entity    int
		expected  bool
	}{
		{
			name:      "true OR true",
			predicate: alwaysTrue,
			other:     alwaysTrue,
			entity:    1,
			expected:  true,
		},
		{
			name:      "true OR false",
			predicate: alwaysTrue,
			other:     alwaysFalse,
			entity:    1,
			expected:  true,
		},
		{
			name:      "false OR true",
			predicate: alwaysFalse,
			other:     alwaysTrue,
			entity:    1,
			expected:  true,
		},
		{
			name:      "false OR false",
			predicate: alwaysFalse,
			other:     alwaysFalse,
			entity:    1,
			expected:  false,
		},
		{
			name:      "isTen OR true (entity 10)",
			predicate: isTen,
			other:     alwaysTrue,
			entity:    10,
			expected:  true,
		},
		{
			name:      "isTen OR true (entity 5)",
			predicate: isTen,
			other:     alwaysTrue,
			entity:    5,
			expected:  true, // isTen is false, but alwaysTrue is true
		},
		{
			name:      "isTen OR false (entity 10)",
			predicate: isTen,
			other:     alwaysFalse,
			entity:    10,
			expected:  true,
		},
		{
			name:      "isTen OR false (entity 5)",
			predicate: isTen,
			other:     alwaysFalse,
			entity:    5,
			expected:  false, // isTen is false, alwaysFalse is false
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			combined := tc.predicate.Or(tc.other)
			actual := combined.IsSatisfiedBy(tc.entity)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestPredicate_Not(t *testing.T) {
	alwaysTrue := baccess.Predicate[int](func(i int) bool { return true })
	alwaysFalse := baccess.Predicate[int](func(i int) bool { return false })
	isTen := baccess.Predicate[int](func(i int) bool { return i == 10 })

	testCases := []struct {
		name      string
		predicate baccess.Predicate[int]
		entity    int
		expected  bool
	}{
		{
			name:      "NOT true",
			predicate: alwaysTrue,
			entity:    1,
			expected:  false,
		},
		{
			name:      "NOT false",
			predicate: alwaysFalse,
			entity:    1,
			expected:  true,
		},
		{
			name:      "NOT isTen (entity 10)",
			predicate: isTen,
			entity:    10,
			expected:  false,
		},
		{
			name:      "NOT isTen (entity 5)",
			predicate: isTen,
			entity:    5,
			expected:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			negated := tc.predicate.Not()
			actual := negated.IsSatisfiedBy(tc.entity)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
