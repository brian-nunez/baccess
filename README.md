# baccess: Predicate-Based Authorization Library for Go

`baccess` is a powerful and flexible Go library for implementing fine-grained, predicate-based authorization in your applications. It allows you to define access control policies using composable boolean functions (predicates) and evaluate them efficiently against access requests.

Inspired by the "Predicate Pattern", `baccess` brings together Role-Based Access Control (RBAC) and Attribute-Based Access Control (ABAC) principles in a generic and highly performant manner.

## Features

-   **Predicate-Based Design:** Build complex authorization logic by combining simple, reusable boolean functions (`Predicate`s).
-   **Generic & Type-Safe:** Leverage Go's generics to define subjects and resources specific to your domain, ensuring type safety throughout your authorization policies.
-   **Boolean Logic Composition:** Easily combine predicates using `And()`, `Or()`, and `Not()` operations to express sophisticated access rules.
-   **Declarative Policy Configuration:** Define your authorization policies in a structured format (e.g., JSON), mapping roles to actions and conditions.
-   **Pluggable Predicates:** Register custom application-specific predicates and reference them by name in your configurations.
-   **Efficient Evaluation:** Designed for high performance with minimal memory allocations during policy evaluation.
-   **RBAC Support:** Built-in utilities for checking subject roles (`RoleBearer` interface).
-   **ABAC Support:** Interfaces (`Attributable`) to facilitate attribute-based access control.

## 🚀 Getting Started

Here's a quick example of how you might set up and use `baccess`:

**1. Define your Subject and Resource types:**

```go
package main

import (
    "github.com/brian-nunez/baccess"
)

type User struct {
    ID    string
    Roles []string
}

func (u User) GetRoles() []string { return u.Roles } // Implement baccess.RoleBearer

type Document struct {
    OwnerID string
    Public  bool
}

// AccessRequest will be baccess.AccessRequest[User, Document]
```

**2. Define your Policies (e.g., in `config.json`):**

```json
{
  "policies": {
    "admin": {
      "allow": ["*"]
    },
    "editor": {
      "allow": [
        "read",
        "write",
        "delete:isOwner"
      ]
    },
    "viewer": {
      "allow": ["read"]
    }
  }
}
```

**3. Set up the Evaluator in your Go application:**

```go
package main

import (
	"fmt"
	"log"

	"github.com/brian-nunez/baccess"
)

// User and Document types defined as above

func main() {
	// Initialize RBAC (optional, but good practice for role checks)
	rbac := baccess.NewRBAC[User, Document]()

	// Create a registry and register custom predicates
	registry := baccess.NewRegistry[User, Document]()
	registry.Register("isOwner", baccess.FieldEquals(
		func(u User) string { return u.ID },
		func(d Document) string { return d.OwnerID },
	))
    registry.Register("isPublic", baccess.ResourceMatches(
        func(d Document) bool { return d.Public },
        true,
    ))

	// Load configuration
	cfg, err := baccess.LoadConfigFromFile("config.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Build the Evaluator
	evaluator, err := baccess.BuildEvaluator(cfg, rbac, registry)
	if err != nil {
		log.Fatalf("Error building evaluator: %v", err)
	}

	// Example usage
	admin := User{ID: "admin1", Roles: []string{"admin"}}
	editor := User{ID: "editor1", Roles: []string{"editor"}}
	viewer := User{ID: "viewer1", Roles: []string{"viewer"}}

	doc1 := Document{OwnerID: "editor1", Public: false}
	doc2 := Document{OwnerID: "other", Public: true}

	req1 := baccess.AccessRequest[User, Document]{Subject: admin, Resource: doc1, Action: "any:action"}
	fmt.Printf("Admin can 'any:action' on doc1: %v
", evaluator.Evaluate(req1)) // true

	req2 := baccess.AccessRequest[User, Document]{Subject: editor, Resource: doc1, Action: "delete:isOwner"}
	fmt.Printf("Editor can delete own doc1: %v
", evaluator.Evaluate(req2)) // true

	req3 := baccess.AccessRequest[User, Document]{Subject: viewer, Resource: doc2, Action: "read"}
	fmt.Printf("Viewer can read public doc2: %v
", evaluator.Evaluate(req3)) // true (assuming "read" policy is general)

	req4 := baccess.AccessRequest[User, Document]{Subject: viewer, Resource: doc1, Action: "delete:isOwner"}
	fmt.Printf("Viewer can delete doc1: %v
", evaluator.Evaluate(req4)) // false
}
```

For a more comprehensive example, please refer to `cmd/main.go` in the repository.

## Documentation

For in-depth technical details, API reference, and architecture overview, please see the [baccess_documentation.md](baccess_documentation.md) file.

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

## License

This project is licensed under the [MIT License](LICENSE).

## Contact

For questions, feedback, or support, please reach out to `baccess@bjnunez.com`.

