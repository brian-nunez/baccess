package auth

import "brian-nunez/baccess/pkg/predicates"

func IsOwner[S Identifiable, R Ownable]() predicates.Predicate[AccessRequest[S, R]] {
	return func(req AccessRequest[S, R]) bool {
		return req.Subject.GetID() == req.Resource.GetOwnerID()
	}
}

func AttrGreaterThan[S Attributable, R any](key string, val int) predicates.Predicate[AccessRequest[S, R]] {
	return func(req AccessRequest[S, R]) bool {
		attr := req.Subject.GetAttribute(key)
		if v, ok := attr.(int); ok {
			return v > val
		}

		return false
	}
}
