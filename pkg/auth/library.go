package auth

import (
	"brian-nunez/baccess/pkg/predicates"
	"slices"
)

func Allow[S any, R any]() predicates.Predicate[AccessRequest[S, R]] {
	return func(req AccessRequest[S, R]) bool { return true }
}

func Deny[S any, R any]() predicates.Predicate[AccessRequest[S, R]] {
	return func(req AccessRequest[S, R]) bool { return false }
}

func FieldEquals[S any, R any, T comparable](
	subjVal func(S) T,
	resVal func(R) T,
) predicates.Predicate[AccessRequest[S, R]] {
	return func(req AccessRequest[S, R]) bool {
		return subjVal(req.Subject) == resVal(req.Resource)
	}
}

func FieldNotEquals[S any, R any, T comparable](
	subjVal func(S) T,
	resVal func(R) T,
) predicates.Predicate[AccessRequest[S, R]] {
	return func(req AccessRequest[S, R]) bool {
		return subjVal(req.Subject) != resVal(req.Resource)
	}
}

func SubjectMatches[S any, R any, T comparable](
	extractor func(S) T,
	target T,
) predicates.Predicate[AccessRequest[S, R]] {
	return func(req AccessRequest[S, R]) bool {
		return extractor(req.Subject) == target
	}
}

func ResourceMatches[S any, R any, T comparable](
	extractor func(R) T,
	target T,
) predicates.Predicate[AccessRequest[S, R]] {
	return func(req AccessRequest[S, R]) bool {
		return extractor(req.Resource) == target
	}
}

func SubjectInResourceList[S any, R any, T comparable](
	subjVal func(S) T,
	resList func(R) []T,
) predicates.Predicate[AccessRequest[S, R]] {
	return func(req AccessRequest[S, R]) bool {
		val := subjVal(req.Subject)
		list := resList(req.Resource)

		return slices.Contains(list, val)
	}
}

func ListIntersection[S any, R any, T comparable](
	subjList func(S) []T,
	resList func(R) []T,
) predicates.Predicate[AccessRequest[S, R]] {
	return func(req AccessRequest[S, R]) bool {
		sList := subjList(req.Subject)
		rList := resList(req.Resource)

		for _, s := range sList {
			if slices.Contains(rList, s) {
				return true
			}
		}

		return false
	}
}

func SubjectAttrEquals[S Attributable, R any](key string, val any) predicates.Predicate[AccessRequest[S, R]] {
	return func(req AccessRequest[S, R]) bool {
		return req.Subject.GetAttribute(key) == val
	}
}

func SubjectAttrGT[S Attributable, R any](key string, threshold int) predicates.Predicate[AccessRequest[S, R]] {
	return func(req AccessRequest[S, R]) bool {
		attr := req.Subject.GetAttribute(key)
		if v, ok := attr.(int); ok {
			return v > threshold
		}

		return false
	}
}

func SubjectAttrLT[S Attributable, R any](key string, threshold int) predicates.Predicate[AccessRequest[S, R]] {
	return func(req AccessRequest[S, R]) bool {
		attr := req.Subject.GetAttribute(key)
		if v, ok := attr.(int); ok {
			return v < threshold
		}

		return false
	}
}

func SubjectAttrTrue[S Attributable, R any](key string) predicates.Predicate[AccessRequest[S, R]] {
	return func(req AccessRequest[S, R]) bool {
		attr := req.Subject.GetAttribute(key)
		if v, ok := attr.(bool); ok {
			return v
		}

		return false
	}
}
