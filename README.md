# baccess

**baccess** is a flexible, predicate-based authorization library for Go. It combines Role-Based Access Control (RBAC) and Attribute-Based Access Control (ABAC) into a unified, chainable, and configuration-driven system.

## Key Features

- **Predicate-Based Logic**: Policies are functions ($f(x) \to bool$) that can be composed using `And`, `Or`, and `Not`.
- **Hybrid RBAC & ABAC**: Seamlessly mix role checks with deep attribute inspections of Subjects and Resources.
- **Dynamic Configuration**: Load access policies from JSON files without recompiling.
- **Type-Safe**: Built on Go generics (`T any`) to ensure type safety for your specific User and Resource structs.
- **Extensible**: Easily register custom predicates to handle complex business rules.

## Installation

```bash
go get github.com/brian-nunez/baccess/v1
```

## Quick Start

### 1. Define your Types

Implement the necessary interfaces (`RoleBearer`, `Identifiable`, `Attributable`) on your User struct.

```go
type User struct {
    ID    string
    Roles []string
    Attrs map[string]any
}

func (u User) GetRoles() []string { return u.Roles }
// ... implement other methods if needed for specific predicates
```

### 2. Configure & Evaluate

```go
package main

import (
    "fmt"
    baccess "github.com/brian-nunez/baccess/v1"
)

func main() {
    // 1. Setup Core Components
    rbac := baccess.NewRBAC[User, Document]()
    registry := baccess.NewRegistry[User, Document]()

    // 2. Register Custom Logic (ABAC)
    // "isOwner" checks if User.ID == Document.OwnerID
    registry.Register("isOwner", baccess.FieldEquals(
        func(u User) string { return u.ID },
        func(d Document) string { return d.OwnerID },
    ))

    // 3. Load Policy from JSON
    // policies: { "editor": { "allow": ["delete:isOwner"] } }
    cfg, _ := baccess.LoadConfigFromFile("config.json")
    
    // 4. Build the Evaluator
    evaluator, _ := baccess.BuildEvaluator(cfg, rbac, registry)

    // 5. Check Access
    req := baccess.AccessRequest[User, Document]{
        Subject:  User{ID: "alice", Roles: []string{"editor"}},
        Resource: Document{OwnerID: "alice"},
        Action:   "delete",
    }

    if evaluator.Evaluate(req) {
        fmt.Println("Access Granted!")
    } else {
        fmt.Println("Access Denied.")
    }
}
```

## Documentation

- [Configuration Guide](docs/CONFIGURATION.md): Learn how to define policies in JSON, including wildcards and syntax.
- [Predicate Library](docs/PREDICATES.md): Explore the built-in predicates and learn how to write your own.

## Core Concepts

### AccessRequest
Every check revolves around an `AccessRequest[S, R]`, which bundles:
- **Subject** (`S`): Who is making the request? (e.g., User)
- **Resource** (`R`): What is being accessed? (e.g., Document, File)
- **Action** (`string`): What are they trying to do? (e.g., "read", "delete")

### The Evaluator
The `Evaluator` determines if a request is allowed. It maps an **Action** to a composite **Predicate**. 
If multiple policies allow the same action (e.g., via different roles), they are combined with `OR`—access is granted if *any* policy allows it.

### Predicates
A `Predicate` is simply a function: `type Predicate[T] func(T) bool`.
They are the building blocks of `baccess`. You can chain them:

```go
// Allow if (Admin) OR (Editor AND IsOwner)
policy := IsAdmin.Or(IsEditor.And(IsOwner))
```
