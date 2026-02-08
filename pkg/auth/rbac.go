package auth

import (
	"brian-nunez/baccess/pkg/predicates"
	"slices"
)

// HasRole creates a predicate that checks if the subject has the exact role.
func HasRole[S RoleBearer, R any](role string) predicates.Predicate[AccessRequest[S, R]] {
	return func(req AccessRequest[S, R]) bool {
		roles := req.Subject.GetRoles()

		return slices.Contains(roles, role)
	}
}

// HasAnyRole creates a predicate that checks if the subject has any of the specified roles.
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
	// Parent -> []Children
	// e.g. "admin" -> ["editor", "viewer"]
	Hierarchy map[string][]string
}

func NewRBAC[S RoleBearer, R any](hierarchy map[string][]string) *RBAC[S, R] {
	return &RBAC[S, R]{Hierarchy: hierarchy}
}

// HasRole creates a predicate that checks if the subject has the role or any parent role that implies it.
func (rbac *RBAC[S, R]) HasRole(targetRole string) predicates.Predicate[AccessRequest[S, R]] {
	return func(req AccessRequest[S, R]) bool {
		userRoles := req.Subject.GetRoles()

		for _, ur := range userRoles {
			if rbac.roleMatches(ur, targetRole) {
				return true
			}
		}

		return false
	}
}

// HasAnyRole creates a predicate that checks if the subject has any of the target roles (considering hierarchy).
func (rbac *RBAC[S, R]) HasAnyRole(targetRoles ...string) predicates.Predicate[AccessRequest[S, R]] {
	return func(req AccessRequest[S, R]) bool {
		userRoles := req.Subject.GetRoles()

		for _, ur := range userRoles {
			for _, tr := range targetRoles {
				if rbac.roleMatches(ur, tr) {
					return true
				}
			}
		}

		return false
	}
}

func (rbac *RBAC[S, R]) roleMatches(userRole, targetRole string) bool {
	if userRole == targetRole {
		return true
	}

	// Check if userRole is a parent of targetRole (i.e., userRole implies targetRole)
	if children, ok := rbac.Hierarchy[userRole]; ok {
		for _, child := range children {
			if rbac.roleMatches(child, targetRole) {
				return true
			}
		}
	}

	return false
}
