package auth

type AccessRequest[S any, R any] struct {
	Subject  S
	Resource R
	Action   string
}

type RoleBearer interface {
	GetRoles() []string
}

type Identifiable interface {
	GetID() any
}

type Ownable interface {
	GetOwnerID() any
}

type Attributable interface {
	GetAttribute(key string) any
}

