package auth_test_utils

import baccess "github.com/brian-nunez/baccess/v1"

var _ baccess.RoleBearer = MockRoleBearer{}
var _ baccess.Identifiable = MockIdentifiable{}
var _ baccess.Attributable = MockAttributable{}
var _ baccess.RoleBearer = MockSubject{}
var _ baccess.Identifiable = MockSubject{}
var _ baccess.Attributable = MockSubject{}
var _ baccess.Identifiable = MockResource{}
var _ baccess.Attributable = MockResource{}

type MockRoleBearer struct {
	Roles []string
}

func (m MockRoleBearer) GetRoles() []string {
	return m.Roles
}

type MockIdentifiable struct {
	ID any
}

func (m MockIdentifiable) GetID() any {
	return m.ID
}

type MockAttributable struct {
	Attributes map[string]any
}

func (m MockAttributable) GetAttribute(key string) any {
	return m.Attributes[key]
}

type MockSubject struct {
	ID         string
	Roles      []string
	Department string
	IsActive   bool
	Rank       int
	Tags       []string
	Attributes map[string]any
}

func (m MockSubject) GetID() any {
	return m.ID
}

func (m MockSubject) GetRoles() []string {
	return m.Roles
}

func (m MockSubject) GetAttribute(key string) any {
	return m.Attributes[key]
}

type MockResource struct {
	ID            string
	OwnerID       string
	Status        string
	Permissions   []string
	Collaborators []string
	Attributes    map[string]any
}

func (m MockResource) GetID() any {
	return m.ID
}

func (m MockResource) GetAttribute(key string) any {
	return m.Attributes[key]
}
