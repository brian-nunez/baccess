package auth

import (
	"github.com/brian-nunez/baccess/pkg/predicates"
	"slices"
)

func HasRole[S RoleBearer, R any](role string) predicates.Predicate[AccessRequest[S, R]] {
	return func(req AccessRequest[S, R]) bool {
		roles := req.Subject.GetRoles()

		return slices.Contains(roles, role)
	}
}

func HasAnyRole[S RoleBearer, R any](targetRoles ...string) predicates.Predicate[AccessRequest[S, R]] {
	return func(req AccessRequest[S, R]) bool {
		userRoles := req.Subject.GetRoles()

		for _, ur := range userRoles {
			if slices.Contains(targetRoles, ur) {
				return true
			}
		}

		return false
	}
}

type RBAC[S RoleBearer, R any] struct {
}

func NewRBAC[S RoleBearer, R any]() *RBAC[S, R] {
	return &RBAC[S, R]{}
}

// HasRole creates a predicate that checks if the subject has the role.
func (rbac *RBAC[S, R]) HasRole(targetRole string) predicates.Predicate[AccessRequest[S, R]] {
	return func(req AccessRequest[S, R]) bool {
		userRoles := req.Subject.GetRoles()

		return slices.Contains(userRoles, targetRole)
	}
}

// HasAnyRole creates a predicate that checks if the subject has any of the target roles.
func (rbac *RBAC[S, R]) HasAnyRole(targetRoles ...string) predicates.Predicate[AccessRequest[S, R]] {
	return func(req AccessRequest[S, R]) bool {
		userRoles := req.Subject.GetRoles()

		for _, ur := range userRoles {
			if slices.Contains(targetRoles, ur) {
				return true
			}
		}

		return false
	}
}
