# Predicates

The **Predicate** is the fundamental building block of `Baccess`. A predicate is simply a function that returns `true` or `false`, representing the answer to a single authorization question.

## The `Predicate` Type

A `Predicate` is defined as a generic function type:

```go
package predicates

type Predicate[T any] func(T) bool
```

In the context of `Baccess`, the generic type `T` is almost always a `baccess.AccessRequest[S, R]`, where `S` is your Subject type and `R` is your Resource type.

A predicate for checking access would therefore have this signature:
`func(req baccess.AccessRequest[User, Document]) bool`

### Predicate Methods: `And`, `Or`, `Not`

The real power of predicates comes from their composability. `Baccess` provides three methods to combine simple predicates into complex logical structures.

#### `And(other Predicate[T]) Predicate[T]`

The `And` method combines two predicates, returning a new predicate that is only true if **both** of the original predicates are true.

**Example:**
```go
// Predicate 1: User must have the "editor" role.
isEditor := rbac.HasRole("editor")

// Predicate 2: Document must be in "draft" state.
isDraft := baccess.ResourceMatches(
    func(d Document) string { return d.Status },
    "draft",
)

// Combined Predicate: Must be an editor AND the doc must be a draft.
canEditDraft := isEditor.And(isDraft)
```

#### `Or(other Predicate[T]) Predicate[T]`

The `Or` method combines two predicates, returning a new predicate that is true if **either** of the original predicates is true.

**Example:**
```go
// Predicate 1: User is the owner of the document.
isOwner := baccess.FieldEquals(...)

// Predicate 2: User is a collaborator on the document.
isCollaborator := baccess.SubjectInResourceList(...)

// Combined Predicate: Can access if owner OR collaborator.
canAccess := isOwner.Or(isCollaborator)
```

#### `Not() Predicate[T]`

The `Not` method inverts a predicate, returning a new predicate that is true if the original predicate is **false**, and vice-versa.

**Example:**
```go
// Predicate: Checks if a user's account is suspended.
isSuspended := baccess.SubjectAttrTrue("is_suspended")

// Inverted Predicate: True only if the user is NOT suspended.
isNotSuspended := isSuspended.Not()

// You can also write it as baccess.Not(isSuspended)
```

## Creating and Registering Custom Predicates

While the standard library provides many useful predicates, you will often need to define custom logic specific to your application's business rules.

**To create a custom predicate:**

1.  Write a function that matches the `baccess.Predicate` signature.
2.  Register it with a `baccess.Registry` instance.

**Example:** Let's create a predicate that checks if a blog post is being edited within 5 minutes of its creation time.

```go
package main

import (
    baccess "github.com/brian-nunez/baccess/v1"
    "time"
)

// Custom predicate function
func isEditableWithin5Minutes(req baccess.AccessRequest[User, Post]) bool {
    post := req.Resource
    return time.Since(post.CreatedAt) < (5 * time.Minute)
}

func main() {
    // ... setup ...
    registry := baccess.NewRegistry[User, Post]()

    // Register the custom function as a predicate with a specific name.
    registry.Register(
        "isEditableWithin5Minutes",
        baccess.Predicate[baccess.AccessRequest[User, Post]](isEditableWithin5Minutes),
    )

    // Now you can use "isEditableWithin5Minutes" as a condition name
    // in your JSON configuration file.
}
```

## Standard Predicate Library (`library.go`)

`Baccess` includes a standard library of generic, reusable predicates to cover the most common authorization scenarios.

---

### `Allow()` / `Deny()`

These are the most basic predicates.

*   `Allow[S, R]()`: Always returns `true`.
*   `Deny[S, R]()`: Always returns `false`.

**Usage:** Often used as defaults or placeholders. The system uses `Deny()` internally to handle invalid policy configurations safely.

---

### `FieldEquals()`

Compares a value extracted from the Subject with a value extracted from the Resource.

**Signature:** `FieldEquals[S, R, T comparable](subjVal func(S) T, resVal func(R) T)`

*   `subjVal`: A function that extracts a value of type `T` from the Subject.
*   `resVal`: A function that extracts a value of type `T` from the Resource.

**Returns `true` if `subjVal(Subject) == resVal(Resource)`.**

**Example:** Check if the user's ID matches the document's `OwnerID`.
```go
isOwner := baccess.FieldEquals(
    func(u User) string { return u.ID },
    func(d Document) string { return d.OwnerID },
)
// This predicate can be registered with the name "isOwner".
```

---

### `FieldNotEquals()`

The opposite of `FieldEquals`.

**Signature:** `FieldNotEquals[S, R, T comparable](subjVal func(S) T, resVal func(R) T)`

**Returns `true` if `subjVal(Subject) != resVal(Resource)`.**

**Example:** Check if a user is trying to transfer a resource to themselves.
```go
isNotSelfTransfer := baccess.FieldNotEquals(
    func(u User) string { return u.ID },
    func(t TransferRequest) string { return t.RecipientID },
)
```

---

### `SubjectMatches()`

Compares a value extracted from the Subject against a fixed, constant target value.

**Signature:** `SubjectMatches[S, R, T comparable](extractor func(S) T, target T)`

*   `extractor`: A function that extracts a value from the Subject.
*   `target`: The constant value to compare against.

**Example:** Check if the user's department is "finance".
```go
isFinanceUser := baccess.SubjectMatches(
    func(u User) string { return u.Department },
    "finance",
)
```

---

### `ResourceMatches()`

Compares a value extracted from the Resource against a fixed, constant target value.

**Signature:** `ResourceMatches[S, R, T comparable](extractor func(R) T, target T)`

*   `extractor`: A function that extracts a value from the Resource.
*   `target`: The constant value to compare against.

**Example:** Check if a document's status is "published".
```go
isPublished := baccess.ResourceMatches(
    func(d Document) string { return d.Status },
    "published",
)
```

---

### `SubjectInResourceList()`

Checks if a value extracted from the Subject is present in a list (slice) extracted from the Resource.

**Signature:** `SubjectInResourceList[S, R, T comparable](subjVal func(S) T, resList func(R) []T)`

*   `subjVal`: A function that extracts a single value from the Subject.
*   `resList`: A function that extracts a slice of values from the Resource.

**Example:** Check if a user's ID is in a document's list of collaborators.
```go
isCollaborator := baccess.SubjectInResourceList(
    func(u User) string { return u.ID },
    func(d Document) []string { return d.Collaborators },
)
```

---

### `ListIntersection()`

Checks if two lists, one from the Subject and one from the Resource, have at least one element in common.

**Signature:** `ListIntersection[S, R, T comparable](subjList func(S) []T, resList func(R) []T)`

*   `subjList`: A function that extracts a slice of values from the Subject.
*   `resList`: A function that extracts a slice of values from the Resource.

**Example:** Check if any of the user's groups match any of the groups that have access to a folder.
```go
hasGroupAccess := baccess.ListIntersection(
    func(u User) []string { return u.Groups },
    func(f Folder) []string { return f.AllowedGroups },
)
```

---

### `SubjectAttr...` Predicates

These predicates work on Subjects that implement the `baccess.Attributable` interface, which provides a `GetAttribute(key string) any` method. This is useful for checking dynamic attributes that are not strongly typed in your Go structs.

*   **`SubjectAttrEquals(key string, val any)`**: True if `Subject.GetAttribute(key) == val`.
    ```go
    // Checks if the user's "country" attribute is "CA"
    isCanadian := baccess.SubjectAttrEquals("country", "CA")
    ```

*   **`SubjectAttrGT(key string, threshold int)`**: True if the attribute is an `int` and is greater than `threshold`.
    ```go
    // Checks if the user's "security_level" is greater than 5
    isHighSecurity := baccess.SubjectAttrGT("security_level", 5)
    ```

*   **`SubjectAttrLT(key string, threshold int)`**: True if the attribute is an `int` and is less than `threshold`.
    ```go
    // Checks if the user's "login_attempts" is less than 3
    notLockedOut := baccess.SubjectAttrLT("login_attempts", 3)
    ```

*   **`SubjectAttrTrue(key string)`**: True if the attribute is a `bool` and is `true`.
    ```go
    // Checks if the user's "is_verified" attribute is true
    isVerified := baccess.SubjectAttrTrue("is_verified")
    ```
