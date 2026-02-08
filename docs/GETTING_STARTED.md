# Getting Started with Baccess

This guide will walk you through the essential steps to integrate the `Baccess` authorization library into your Go application.

## 1. Installation

To get started, add `Baccess` to your project using `go get`:

```sh
go get github.com/brian-nunez/baccess
```

## 2. Core Concepts in Code

Before building a policy, let's understand the main components you'll interact with.

*   **`auth.AccessRequest[S, R]`**: This struct holds all context for an authorization check. `S` is the generic type for your Subject (user) and `R` is for your Resource.
    *   `Subject S`: The user or entity requesting access.
    *   `Resource R`: The object being accessed.
    -   `Action string`: The operation being performed (e.g., "view", "edit:title").

*   **`predicates.Predicate[T]`**: A function type representing a single authorization rule. It's simply `func(T) bool`. In `Baccess`, `T` is almost always an `auth.AccessRequest`.

*   **`auth.Evaluator[S, R]`**: The engine that evaluates `AccessRequest`s against your policies.

## 3. A Basic Example: Pure Go Setup

Let's create a simple policy entirely in Go, without any external configuration.

**Scenario:** A user must have the `"editor"` role to `"edit"` a document.

### Step 3.1: Define Your Types

First, define the `User` and `Document` types that will be your Subject and Resource. They must satisfy the `auth.RoleBearer` interface if you use the RBAC helpers.

```go
package main

import (
    "brian-nunez/baccess/pkg/auth"
    "fmt"
)

type User struct {
    Roles []string
}

// GetRoles satisfies the auth.RoleBearer interface
func (u User) GetRoles() []string {
    return u.Roles
}

type Document struct {
    Content string
}

func main() {
    // ... setup coming next
}
```

### Step 3.2: Create the Evaluator and RBAC Helper

Instantiate the `Evaluator` and the `RBAC` helper.

```go
    // Inside main()
    evaluator := auth.NewEvaluator[User, Document]()
    rbac := auth.NewRBAC[User, Document]()
```

### Step 3.3: Define and Add the Policy

Create the predicate that defines the logic for editing. In this case, it's just checking for the "editor" role. Then, add it to the evaluator for the "edit" action.

```go
    // Inside main()

    // The predicate checks if the subject has the "editor" role.
    canEditPolicy := rbac.HasRole("editor")

    // Associate the "edit" action with our policy.
    evaluator.AddPolicy("edit", canEditPolicy)
```

### Step 3.4: Evaluate Access

Now, create your users and resources and evaluate their access.

```go
    // Inside main()
    editor := User{Roles: []string{"editor"}}
    viewer := User{Roles: []string{"viewer"}}
    doc := Document{Content: "A test document."}

    // --- Check 1: Editor tries to edit ---
    req1 := auth.AccessRequest[User, Document]{
        Subject:  editor,
        Resource: doc,
        Action:   "edit",
    }
    canEditorEdit := evaluator.Evaluate(req1)
    fmt.Printf("Editor can edit: %v (Expected: true)
", canEditorEdit)

    // --- Check 2: Viewer tries to edit ---
    req2 := auth.AccessRequest[User, Document]{
        Subject:  viewer,
        Resource: doc,
        Action:   "edit",
    }
    canViewerEdit := evaluator.Evaluate(req2)
    fmt.Printf("Viewer can edit: %v (Expected: false)
", canViewerEdit)
}
```

### Full Example Code

```go
package main

import (
	"brian-nunez/baccess/pkg/auth"
	"fmt"
)

type User struct {
	Roles []string
}

func (u User) GetRoles() []string {
	return u.Roles
}

type Document struct {
	Content string
}

func main() {
	// 1. Setup
	evaluator := auth.NewEvaluator[User, Document]()
	rbac := auth.NewRBAC[User, Document]()

	// 2. Define Policy
	canEditPolicy := rbac.HasRole("editor")
	evaluator.AddPolicy("edit", canEditPolicy)

	// 3. Create Subjects and Resources
	editor := User{Roles: []string{"editor"}}
	viewer := User{Roles: []string{"viewer"}}
	doc := Document{Content: "A test document."}

	// 4. Evaluate
	req1 := auth.AccessRequest[User, Document]{
		Subject:  editor,
		Resource: doc,
		Action:   "edit",
	}
	fmt.Printf("Editor can edit: %v (Expected: true)
", evaluator.Evaluate(req1))

	req2 := auth.AccessRequest[User, Document]{
		Subject:  viewer,
		Resource: doc,
		Action:   "edit",
	}
	fmt.Printf("Viewer can edit: %v (Expected: false)
", evaluator.Evaluate(req2))
}
```

This example covers the simplest use case. From here, you can explore more complex scenarios by building more complex predicates, which is covered in the `PREDICATES.md` and `EXAMPLES.md` documentation.
