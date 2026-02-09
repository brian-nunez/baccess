# Project: Go Predicate-Based Authorization (RBAC & ABAC)

## Goal
Build a Go package for authorization that uses functional Predicates to evaluate RBAC (Role-Based) and ABAC (Attribute-Based) access control. The package allows for highly readable, chainable policy definitions in code, as well as dynamic policy loading from JSON configuration.

## Core Principle
The system uses the "Predicate Pattern": $f(x) \to bool$. 
Complex policies are built by composing simple predicates using `And()`, `Or()`, and `Not()` methods.

## Implemented Features

### 1. Core Predicates (`pkg/predicates`)
- Generic `Predicate[T]` type.
- Combinators: `And`, `Or`, `Not`.
- Method `IsSatisfiedBy(entity T) bool`.

### 2. Authorization Context (`pkg/auth/types.go`)
- `AccessRequest[S, R]`: Encapsulates Subject, Resource, and Action.
- Interfaces: `RoleBearer`, `Identifiable`, `Attributable`.

### 3. RBAC Layer (`pkg/auth/rbac.go`)
- `HasRole(role)`: Checks if the Subject possesses a specific role.
- `HasAnyRole(roles...)`: Checks if the Subject possesses any of the specified roles.
- *Note*: The current `RBAC` implementation relies on the Subject's provided list of roles and does not internally manage hierarchy.

### 4. Predicate Library (`pkg/auth/library.go`)
Provides a suite of generic, reusable predicates to build ABAC policies:
- `Allow()`, `Deny()`: Basic boolean predicates.
- `FieldEquals`, `FieldNotEquals`: Compares extracted values from Subject and Resource.
- `SubjectMatches`, `ResourceMatches`: Checks extracted value against a constant target.
- `SubjectInResourceList`: Checks if a Subject value is present in a list on the Resource.
- `ListIntersection`: Checks if Subject and Resource lists share any elements.
- `SubjectAttrEquals`, `SubjectAttrGT`, `SubjectAttrLT`, `SubjectAttrTrue`: Evaluates dynamic attributes on the Subject.

### 5. Policy Management (`pkg/auth/policy.go`)
- `Evaluator[S, R]`: Maps "Actions" to "Predicates".
- **Wildcard Support**: Policies for `*` actions apply to all requests (useful for Superusers).
- **Composition**: Multiple policies for the same action are automatically `OR`-ed together.

### 6. Configuration Loading (`pkg/config`)
- JSON-based policy definition.
- Rule syntax: `action:predicate_name` (e.g., `delete:isOwner`).
- Binds string names in JSON to Go functions via a `Registry` (implementing `PredicateProvider`).

## Project Structure
```
/
├── cmd/
│   ├── config.json       # Policy definitions
│   └── main.go           # Application entry point / Example usage
└── pkg/
    ├── auth/
    │   ├── library.go    # Standard library of reusable predicates
    │   ├── policy.go     # Evaluator logic
    │   ├── rbac.go       # Role-based access control predicates
    │   ├── registry.go   # Predicate registry for dynamic lookup
    │   └── types.go      # Core interfaces and AccessRequest type
    ├── config/           # JSON Loader and Policy Builder
    └── predicates/       # Core generic predicate logic
```

## Configuration Format (`config.json`)

The configuration maps **Roles** to a list of allowed **Rules**.

```json
{
  "policies": {
    "admin": {
      "allow": ["*"] 
    },
    "editor": {
      "allow": [
        "read:*",          // Can always read
        "delete:isOwner"   // Can delete ONLY if "isOwner" predicate is true
      ]
    }
  }
}
```

- **Rule Syntax**: `action` OR `action:condition`
- **Wildcards**: `*` as an action means "Any Action". `*` as a condition means "Always True".

## Usage Example

```go
// 1. Setup
rabc := auth.NewRBAC[User, Document]()
registry := auth.NewRegistry[User, Document]()

// 2. Register Custom Predicates using the Library
registry.Register("isOwner", auth.FieldEquals(
    func(u User) string { return u.ID },
    func(d Document) string { return d.OwnerID },
))

registry.Register("isCollaborator", auth.SubjectInResourceList(
    func(u User) string { return u.ID },
    func(d Document) []string { return d.Collaborators },
))

// 3. Load Config & Build Evaluator
cfg, _ := config.LoadConfigFromFile("cmd/config.json")
evaluator, _ := config.BuildEvaluator(cfg, rbac, registry)

// 4. Evaluate Access
req := auth.AccessRequest[User, Document]{
    Subject:  editorUser,
    Resource: doc,
    Action:   "delete",
}
allowed := evaluator.Evaluate(req)
```
