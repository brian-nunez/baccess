<p align="center">
  <img src="docs/brand/icon.svg" width="128" height="128" alt="Project icon: a white authorization shield and check mark on a blue gradient">
</p>

<h1 align="center">baccess</h1>

<p align="center">
  <b>Predicate-based authorization for Go; compose type-safe RBAC and attribute-aware policies for fine-grained access decisions.</b>
</p>

<p align="center">
  baccess is a generic Go library for building fast, composable authorization policies around your subjects, resources, and actions.<br>
  <i>By Brian Nunez.</i>
</p>

<p align="center">
  <img alt="Written in Go" src="https://img.shields.io/badge/written%20in-Go-00758f?style=flat-square&logo=go&logoColor=white">
  <img alt="Requires Go 1.25" src="https://img.shields.io/badge/requires-Go%201.25-00add8?style=flat-square&logo=go&logoColor=white">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-00758f?style=flat-square">
  <img alt="Generic library" src="https://img.shields.io/badge/design-generic%20library-00add8?style=flat-square">
  <br>
  <a href="https://github.com/brian-nunez/baccess/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/brian-nunez/baccess?style=flat-square&logo=github"></a>
  <a href="https://pkg.go.dev/github.com/brian-nunez/baccess"><img alt="Go Reference" src="https://pkg.go.dev/badge/github.com/brian-nunez/baccess.svg"></a>
</p>

<p align="center">
  <a href="https://pkg.go.dev/github.com/brian-nunez/baccess"><img alt="View Go docs" src="https://img.shields.io/badge/View%20Go%20docs-526CFE?style=for-the-badge&logo=go&logoColor=white" height="40"></a>
</p>

<p align="center">
  <a href="https://pkg.go.dev/github.com/brian-nunez/baccess"><b>Go docs</b></a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#examples">Examples</a> ·
  <a href="#api-reference">API reference</a> ·
  <a href="#running-tests">Tests</a> ·
  <a href="#license">License</a>
</p>

> [!NOTE]
> **Policies default to deny.** An access request is allowed only when at least one matching policy predicate is satisfied.

## Why baccess

- **Composable.** Build policy logic from reusable predicates with `And`, `Or`, and `Not`.
- **Type-safe.** Generic subjects and resources keep authorization checks tied to your application types.
- **Fine-grained.** Combine roles with ownership, membership, resource state, lists, and subject attributes.
- **Declarative.** Load role policies from JSON or Go maps, then resolve named conditions through a registry.
- **Lightweight.** The library uses the Go standard library at runtime and has no production dependencies.

## Quick start

Install the module:

```bash
go get github.com/brian-nunez/baccess
```

Define your subject and resource types, register a predicate, and build an evaluator from policy configuration:

```go
package main

import (
	"fmt"
	"log"

	"github.com/brian-nunez/baccess"
)

type User struct {
	ID    string
	Roles []string
}

func (u User) GetRoles() []string { return u.Roles }

type Document struct {
	OwnerID string
}

func main() {
	cfg, err := baccess.LoadConfigFromMap(map[string]any{
		"policies": map[string]any{
			"editor": map[string]any{
				"allow": []string{"edit:isOwner"},
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	rbac := baccess.NewRBAC[User, Document]()
	registry := baccess.NewRegistry[User, Document]()
	registry.Register("isOwner", baccess.FieldEquals(
		func(u User) string { return u.ID },
		func(d Document) string { return d.OwnerID },
	))

	evaluator, err := baccess.BuildEvaluator(cfg, rbac, registry)
	if err != nil {
		log.Fatal(err)
	}

	request := baccess.AccessRequest[User, Document]{
		Subject:  User{ID: "alice", Roles: []string{"editor"}},
		Resource: Document{OwnerID: "alice"},
		Action:   "edit:isOwner",
	}
	fmt.Println(evaluator.Evaluate(request)) // true
}
```

## Features

### Predicate composition

| Feature | Description |
| ------- | ----------- |
| **Boolean composition** | Combine predicates with `And`, `Or`, and `Not`, or use the `Allow` and `Deny` helpers. |
| **Custom predicates** | Define any `Predicate[AccessRequest[S, R]]` function for application-specific rules. |
| **Reusable builders** | Compare subject and resource fields, match values, test list membership, and detect list intersections. |

### Policy evaluation

| Feature | Description |
| ------- | ----------- |
| **RBAC** | Match exact subject roles with `HasRole`, `HasAnyRole`, or role-aware configured policies. |
| **ABAC-style checks** | Evaluate subject attributes and resource values through `Attributable` and generic predicate builders. |
| **Action matching** | Support exact actions, conditional actions such as `delete:isOwner`, action wildcards such as `read:*`, and global `*` policies. |
| **Default deny** | Requests with no matching satisfied policy return `false`. |

### Configuration

| Feature | Description |
| ------- | ----------- |
| **JSON policies** | Load configuration from a JSON file with `LoadConfigFromFile`. |
| **In-memory policies** | Build equivalent configuration from `map[string]any` with `LoadConfigFromMap`. |
| **Named conditions** | Register predicates by name and resolve them while `BuildEvaluator` compiles the policy set. |

## Installation

Install baccess with Go:

```bash
go get github.com/brian-nunez/baccess
```

The module requires Go 1.25 or newer.

## Examples

The repository includes runnable examples for:

- [Basic RBAC](examples/01_basic_rbac/main.go)
- [Ownership checks](examples/02_ownership/main.go)
- [Collaboration and membership](examples/03_collaboration/main.go)
- [Group access](examples/04_group_access/main.go)
- [Wildcards](examples/05_wildcards/main.go)
- [Attribute constraints](examples/06_attribute_constraints/main.go)
- [Custom predicate logic](examples/07_custom_logic/main.go)
- [Pure Go evaluator setup](examples/08_pure_go_setup/main.go)
- [Negative logic](examples/09_negative_logic/main.go)
- [Workflow state](examples/10_workflow_state/main.go)

Run an example from the repository root:

```bash
go run ./examples/02_ownership
```

## API reference

The complete generated API documentation is available on [pkg.go.dev](https://pkg.go.dev/github.com/brian-nunez/baccess).

### Core types

```go
type AccessRequest[S any, R any] struct {
	Subject  S
	Resource R
	Action   string
}

type Predicate[T any] func(T) bool

type Evaluator[S any, R any] struct
type Registry[S any, R any] struct
type RBAC[S RoleBearer, R any] struct
```

### Main constructors and operations

```go
func NewEvaluator[S any, R any]() *Evaluator[S, R]
func (e *Evaluator[S, R]) AddPolicy(action string, p Predicate[AccessRequest[S, R]])
func (e *Evaluator[S, R]) Evaluate(req AccessRequest[S, R]) bool

func NewRBAC[S RoleBearer, R any]() *RBAC[S, R]
func NewRegistry[S any, R any]() *Registry[S, R]
func BuildEvaluator[S RoleBearer, R any](
	cfg *Config,
	rbac *RBAC[S, R],
	provider PredicateProvider[S, R],
) (*Evaluator[S, R], error)
```

## Running tests

Run the complete test suite:

```bash
go test ./...
```

The Makefile also provides:

```bash
make test      # tidy modules and run tests
make coverage  # generate coverage.html and print total coverage
make perf      # run the benchmark suite
make clean     # remove generated coverage files and test cache
```

## Documentation

- [Technical documentation](TECHNICAL.md)
- [Go package documentation](https://pkg.go.dev/github.com/brian-nunez/baccess)

## Contributing

Contributions are welcome. Please open an issue or submit a pull request on [GitHub](https://github.com/brian-nunez/baccess).

## Feedback

For questions, feedback, or support, email `baccess@bjnunez.com` or [open an issue](https://github.com/brian-nunez/baccess/issues).

## License

baccess is licensed under the [MIT License](LICENSE).
