package predicates

type Predicate[T any] func(T) bool

func (p Predicate[T]) IsSatisfiedBy(entity T) bool {
	return p(entity)
}

func (p Predicate[T]) And(other Predicate[T]) Predicate[T] {
	return func(entity T) bool {
		return p(entity) && other(entity)
	}
}

func (p Predicate[T]) Or(other Predicate[T]) Predicate[T] {
	return func(entity T) bool {
		return p(entity) || other(entity)
	}
}

func (p Predicate[T]) Not() Predicate[T] {
	return func(entity T) bool {
		return !p(entity)
	}
}
