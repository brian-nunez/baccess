# Baccess by Example

This document provides a detailed walkthrough of the examples found in the `/examples` directory. Each example is designed to highlight a specific feature or use case of the `Baccess` library.

---

## Example 01: Basic RBAC

*Goal: Demonstrate the simplest Role-Based Access Control (RBAC) setup.*

### Policy
```go
cfgData := map[string]any{
    "policies": map[string]any{
        "admin": map[string]any{"allow": []string{"delete", "read"}},
        "guest": map[string]any{"allow": []string{"read"}},
    },
}
```
*   **Logic:** This configuration defines two roles. An `admin` can `"delete"` and `"read"`. A `guest` can only `"read"`. Note that a simple action like `"read"` in the config is treated as an exact match. It does not implicitly mean `"read:*"`.

### Evaluation
```go
// Subjects
admin := User{Name: "Alice", Roles: []string{"admin"}}
guest := User{Name: "Bob", Roles: []string{"guest"}}

// Requests & Results
// 1. Admin tries to delete -> true (Policy "delete" exists for "admin")
// 2. Guest tries to delete -> false (No "delete" policy for "guest")
// 3. Guest tries to read   -> true (Policy "read" exists for "guest")
```

### Full Output
```
Admin delete: true
Guest delete: false
Guest read:   true
```

---

## Example 02: Ownership (ABAC)

*Goal: Demonstrate a simple Attribute-Based Access Control (ABAC) policy using `FieldEquals` to check for resource ownership.*

### Policy
```go
cfgData := map[string]any{
    "policies": map[string]any{
        "user": map[string]any{
            "allow": []string{
                "read:isOwner",
                "edit:isOwner",
            },
        },
    },
}

// Predicate "isOwner" is registered:
registry.Register("isOwner", auth.FieldEquals(
    func(u User) string { return u.ID },
    func(d Document) string { return d.OwnerID },
))
```
*   **Logic:** A user with the `"user"` role is allowed to `"read"` or `"edit"` a resource, but only if the `isOwner` predicate is true. The `isOwner` predicate compares the subject's ID to the resource's `OwnerID`.

### Evaluation
```go
// Subjects
alice := User{ID: "alice", Roles: []string{"user"}}
bob := User{ID: "bob", Roles: []string{"user"}}

// Resource
doc := Document{OwnerID: "alice", Content: "Alice's Diary"}

// Requests & Results
// 1. Alice (owner) tries to edit doc -> true
//    - Action is "edit". Evaluator finds policy "edit:isOwner".
//    - Predicate `isOwner` runs: alice.ID == doc.OwnerID ("alice" == "alice") -> true.
// 2. Bob (not owner) tries to edit doc -> false
//    - Action is "edit". Evaluator finds policy "edit:isOwner".
//    - Predicate `isOwner` runs: bob.ID == doc.OwnerID ("bob" == "alice") -> false.
```

### Full Output
```
Alice edit Alice's doc: true
Bob edit Alice's doc:   false
```

---

## Example 03: Collaboration (ABAC)

*Goal: Show how `SubjectInResourceList` can be used to check for collaboration permissions.*

### Policy
```go
cfgData := map[string]any{
    "policies": map[string]any{
        "user": map[string]any{
            "allow": []string{
                "view:isCollaborator",
            },
        },
    },
}

// Predicate "isCollaborator" is registered:
registry.Register("isCollaborator", auth.SubjectInResourceList(
    func(u User) string { return u.ID },
    func(p Project) []string { return p.Collaborators },
))
```
*   **Logic:** A `"user"` can `"view"` a project if the `isCollaborator` predicate is true. This predicate checks if the user's ID exists within the project's `Collaborators` slice.

### Evaluation
```go
// Subjects
alice := User{ID: "alice", Roles: []string{"user"}}
bob := User{ID: "bob", Roles: []string{"user"}}

// Resource
proj := Project{Collaborators: []string{"alice", "charlie"}}

// Requests & Results
// 1. Alice (collaborator) tries to view -> true
// 2. Bob (not collaborator) tries to view -> false
```

### Full Output
```
Alice can view: true
Bob can view:   false
```

---

## Example 04: Group Access (ABAC)

*Goal: Use `ListIntersection` to check if a user's groups overlap with a resource's allowed groups.*

### Policy
```go
cfgData := map[string]any{
    "policies": map[string]any{
        "user": map[string]any{
            "allow": []string{"access:inAllowedGroup"},
        },
    },
}

// Predicate "inAllowedGroup" is registered:
registry.Register("inAllowedGroup", auth.ListIntersection(
    func(u User) []string { return u.Groups },
    func(r Resource) []string { return r.AllowedGroups },
))
```
*   **Logic:** A `"user"` can `"access"` a resource if the `inAllowedGroup` predicate is true. This predicate checks if any of the user's groups are present in the resource's `AllowedGroups`.

### Evaluation
```go
// Subjects
adminUser := User{Groups: []string{"admin", "dev"}}
devUser := User{Groups: []string{"dev"}}
guestUser := User{Groups: []string{"guest"}}

// Resource
res := Resource{AllowedGroups: []string{"admin", "qa"}}

// Requests & Results
// 1. adminUser tries to access -> true (shares the "admin" group)
// 2. devUser tries to access -> false (no groups in common)
// 3. guestUser tries to access -> false (no groups in common)
```

### Full Output
```
Admin User: true
Dev User:   false
Guest User: false
```

---

## Example 05: Wildcards

*Goal: Demonstrate the use of global (`*`) and action-prefix (`action:*`) wildcards.*

### Policy
```go
cfgData := map[string]any{
    "policies": map[string]any{
        "superuser": {"allow": ["*"]},          // Can do anything
        "editor":    {"allow": ["document:*"]},  // Can do any document action
        "viewer":    {"allow": ["document:read"]}, // Can only read
    },
}
```
*   **Logic:**
    *   `superuser` has `*`, allowing any action.
    *   `editor` has `document:*`, allowing any action prefixed with `document:`, such as `document:edit`, `document:create`, etc.
    *   `viewer` has `document:read`, allowing only that exact action.

### Evaluation
```go
// Subjects
su := User{Roles: []string{"superuser"}}
ed := User{Roles: []string{"editor"}}
vi := User{Roles: []string{"viewer"}}

// Requests & Results
// 1. Superuser edits -> true (matches "*")
// 2. Superuser nukes -> true (matches "*")
// 3. Editor edits -> true (matches "document:*")
// 4. Editor reads -> true (matches "document:*")
// 5. Editor nukes -> false (does not match "document:*" or "*")
// 6. Viewer reads -> true (exact match for "document:read")
// 7. Viewer edits -> false (no match)
```

### Full Output
```
Superuser edit: true
Superuser nuke: true
Editor edit:    true
Editor read:    true
Editor nuke:    false
Viewer read:    true
Viewer edit:    false
```

---

## Example 06: Attribute Constraints

*Goal: Use `ResourceMatches` to enforce ABAC rules based on resource attributes.*

### Policy
```go
cfgData := map[string]any{
    "policies": map[string]any{
        "user": {
            "allow": [
                "read:isPublic",        // Can read if "isPublic" is true
                "read:isInternal",      // OR if "isInternal" is true
                "write:isInternal",     // Can only write if "isInternal" is true
            ],
        },
    },
}

// Predicates registered:
registry.Register("isPublic", auth.ResourceMatches(
    func(d Document) bool { return d.IsPublic }, true,
))
registry.Register("isInternal", auth.ResourceMatches(
    func(d Document) bool { return d.IsInternal }, true,
))
```
*   **Logic:**
    *   A `"user"` can `"read"` if the document is public OR if it's internal.
    *   A `"user"` can `"write"` only if the document is internal.

### Evaluation
```go
// Subjects & Resources
user := User{Roles: []string{"user"}}
publicDoc := Document{IsPublic: true, IsInternal: false}
internalDoc := Document{IsPublic: false, IsInternal: true}
privateDoc := Document{IsPublic: false, IsInternal: false}

// Requests & Results
// 1. Read public doc -> true (matches "read:isPublic")
// 2. Read internal doc -> true (matches "read:isInternal")
// 3. Read private doc -> false (no policy matches)
// 4. Write public doc -> false (no policy matches)
// 5. Write internal doc -> true (matches "write:isInternal")
```

### Full Output
```
Read public doc:   true
Read internal doc: true
Read private doc:  false
Write public doc:  false
Write internal doc:  true
```

---

## Example 07: Custom Logic

*Goal: Show how to register and use a completely custom function as a predicate.*

### Policy
```go
cfgData := map[string]any{
    "policies": map[string]any{
        "moderator": {"allow": ["approve:no_bad_words"]},
    },
}

// Custom predicate function registered as "no_bad_words":
noBadWords := func(req auth.AccessRequest[User, Request]) bool {
    return !strings.Contains(req.Resource.Body, "spam")
}
```
*   **Logic:** A `"moderator"` can `"approve"` a request only if the `no_bad_words` predicate is true. This predicate checks if the resource's body contains the substring "spam".

### Evaluation
```go
// Subject
mod := User{Roles: []string{"moderator"}}

// Resources
goodReq := Request{Body: "Hello world"}
badReq := Request{Body: "Buy this spam now"}

// Requests & Results
// 1. Approve good request -> true (body does not contain "spam")
// 2. Approve bad request -> false (body contains "spam")
```

### Full Output
```
Approve good req: true
Approve bad req:  false
```

---

## Example 08: Pure Go Setup

*Goal: Demonstrate defining policies entirely in Go without using a config file.*

### Policy
```go
// Inside main()
evaluator := auth.NewEvaluator[User, Page]()
rbac := auth.NewRBAC[User, Page]()

// Policy: A user can "view" if they have the "viewer" role.
policy := rbac.HasRole("viewer")

evaluator.AddPolicy("view", policy)
```
*   **Logic:** This setup programmatically builds a policy. The `rbac.HasRole("viewer")` predicate is created and then directly associated with the `"view"` action in the evaluator.

### Evaluation
```go
// Subjects
viewer := User{Roles: []string{"viewer"}}
editor := User{Roles: []string{"editor"}}

// Requests & Results
// 1. Viewer tries to view -> true (has the "viewer" role)
// 2. Editor tries to view -> false (does not have the "viewer" role)
```

### Full Output
```
Viewer can view: true
Editor can view: false
```
---

## Example 09: Negative Logic

*Goal: Show how to use `Not()` to invert the logic of a predicate.*

### Policy
```go
// Predicate to check if a user is suspended
suspended := func(req auth.AccessRequest[User, Page]) bool {
    return req.Subject.Suspended
}

// Policy: Must have "member" role AND must NOT be suspended.
policySimple := rbac.HasRole("member").And(auth.Not(suspended))

evaluator.AddPolicy("view", policySimple)
```
*   **Logic:** This policy is for the `"view"` action. It requires two conditions to be met simultaneously: the user must have the `"member"` role, and the `suspended` predicate must be `false` (inverted by `auth.Not()`).

### Evaluation
```go
// Subjects
active := User{Roles: []string{"member"}, Suspended: false}
banned := User{Roles: []string{"member"}, Suspended: true}

// Requests & Results
// 1. Active member tries to view -> true (is "member" AND not suspended)
// 2. Banned member tries to view -> false (is "member" BUT is suspended)
```

### Full Output
```
Active Member view: true
Banned Member view: false
```

---

## Example 10: Workflow State

*Goal: Demonstrate a multi-step workflow where permissions change based on the resource's state.*

### Policy
```go
cfgData := map[string]any{
    "policies": map[string]any{
        "author": {
            "allow": ["submit:isDraft"], // Can submit if draft
        },
        "reviewer": {
            "allow": ["approve:isPending"], // Can approve if pending
        },
        "publisher": {
            "allow": ["publish:isApproved"], // Can publish if approved
        },
    },
}
// Predicates are registered for "isDraft", "isPending", and "isApproved"
// using auth.ResourceMatches() to check the document's Status field.
```
*   **Logic:** This configuration models a content workflow with three distinct roles and permissions that are only active when the resource is in a specific state.

### Evaluation
```go
// Subjects
author := User{Roles: []string{"author"}}
reviewer := User{Roles: []string{"reviewer"}}

// Resource
doc := Document{Status: "draft"}

// Requests & Results
// 1. Author tries to submit draft -> true (is "author", doc is "draft")
// 2. Reviewer tries to approve draft -> false (doc is "draft", not "pending")
// After changing doc status: doc.Status = "pending"
// 3. Reviewer tries to approve pending -> true (is "reviewer", doc is "pending")
```

### Full Output
```
Author submits draft: true
Reviewer approves draft: false
Reviewer approves pending doc: true
```
