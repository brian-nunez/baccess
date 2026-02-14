# baccess: Predicate-Based Authorization Library

## 1. Introduction

`baccess` is a Go library designed for implementing flexible and high-performance predicate-based authorization. It enables developers to define complex access control policies using a composition of simple boolean functions (predicates) and evaluate them efficiently against access requests. The library supports Role-Based Access Control (RBAC) and Attribute-Based Access Control (ABAC) paradigms through its extensible interfaces and predicate builders.

## 2. Core Concepts

### AccessRequest

The fundamental unit of an authorization decision. It encapsulates the context of a request: who (Subject) is trying to do what (Action) to which (Resource).
-   **Subject (`S`):** The entity requesting access (e.g., user, service account). Can implement `RoleBearer`, `Identifiable`, `Attributable`.
-   **Resource (`R`):** The target of the action (e.g., document, API endpoint). Can implement `Identifiable`, `Attributable`.
-   **Action (`string`):** The operation being attempted (e.g., "read", "write", "delete:isOwner").

### Predicate

A boolean function `func(T) bool` that evaluates a condition about a given entity `T`. In `baccess`, predicates are typically `func(AccessRequest[S, R]) bool`. They can be combined using boolean logic (AND, OR, NOT) to form complex policy rules.

### Evaluator

The central engine responsible for making authorization decisions. It stores a collection of compiled policies (predicates) associated with actions. When an `AccessRequest` is presented, the `Evaluator` matches the request's action against its registered policies and aggregates the results to determine access.

### RBAC (Role-Based Access Control)

`baccess` facilitates RBAC by providing mechanisms to check a subject's roles. Subjects implementing the `RoleBearer` interface can have roles, which are then used in predicates to define role-based policies.

### Registry

A component that allows for registering named predicate functions. This decouples predicate definitions from their usage in declarative policy configurations, enabling dynamic lookup and instantiation of predicates referenced by name.

### Configuration

`baccess` supports declarative policy definitions, typically via JSON. This configuration specifies which roles are allowed to perform which actions, potentially referencing named predicates for conditional checks. The configuration is parsed and translated into executable `Evaluator` policies.

## 3. Component Details

### `types.go`

This file defines the fundamental data structures and interfaces that constitute the core of the `baccess` authorization system. These types enable the representation of access requests, subjects, and resources in a generic and extensible manner.

#### `AccessRequest[S any, R any] struct`

A generic struct representing a request to perform an action on a resource by a subject.

-   **`Subject S`**: The entity attempting to perform an action. `S` can be any type, allowing for flexible representation of users, services, or other actors.
-   **`Resource R`**: The target of the action. `R` can be any type, allowing for flexible representation of data, files, or other system components.
-   **`Action string`**: A string representing the specific operation being requested (e.g., "read", "write", "delete", "admin").

#### `RoleBearer interface`

An interface that defines the capability of an entity to possess roles. Any subject type that needs to be associated with roles for authorization purposes must implement this interface.

-   **`GetRoles() []string`**: Returns a slice of strings representing the roles assigned to the implementing entity.

#### `Identifiable interface`

An interface for entities that can be uniquely identified. This is useful for scenarios where subjects or resources need to be compared or referenced by a distinct identifier.

-   **`GetID() any`**: Returns a generic identifier for the implementing entity.

#### `Attributable interface`

An interface for entities that can provide arbitrary attributes. This allows for attribute-based access control (ABAC) where authorization decisions can depend on dynamic properties of subjects or resources.

-   **`GetAttribute(key string) any`**: Returns the value of a specific attribute identified by `key`.

These types form the foundation upon which predicates, policies, and the evaluation logic are built, enabling a flexible and powerful authorization system.

### `predicate.go`

This file introduces the foundational `Predicate` type and provides methods for composing complex logical conditions from simpler ones using boolean algebra. This is a cornerstone of the `baccess` package, enabling expressive and flexible policy definitions.

#### `type Predicate[T any] func(T) bool`

A `Predicate` is a generic function type that takes an entity of type `T` and returns a boolean value. It represents a single, verifiable condition about an entity. For instance, a `Predicate` might check if a user is an administrator, if a resource is owned by a specific user, or if an action is valid for a given state.

#### `func (p Predicate[T]) IsSatisfiedBy(entity T) bool`

This method evaluates the predicate against a given `entity` of type `T`. It simply executes the underlying function associated with the predicate.

-   **`entity T`**: The entity against which the predicate's condition is checked.
-   **Returns**: `true` if the predicate's condition is met by the entity, `false` otherwise.

#### `func (p Predicate[T]) And(other Predicate[T]) Predicate[T]`

This method combines the current predicate `p` with another predicate `other` using a logical AND operation. The returned `Predicate` will evaluate to `true` only if *both* `p` and `other` predicates are satisfied by the entity. This allows for building policies where multiple conditions must simultaneously hold true.

-   **`other Predicate[T]`**: The predicate to combine with the current one.
-   **Returns**: A new `Predicate[T]` that represents the logical `AND` of `p` and `other`.

#### `func (p Predicate[T]) Or(other Predicate[T]) Predicate[T]`

This method combines the current predicate `p` with another predicate `other` using a logical OR operation. The returned `Predicate` will evaluate to `true` if *at least one* of `p` or `other` predicates is satisfied by the entity. This is useful for policies where any of several conditions can grant access.

-   **`other Predicate[T]`**: The predicate to combine with the current one.
-   **Returns**: A new `Predicate[T]` that represents the logical `OR` of `p` and `other`.

#### `func (p Predicate[T]) Not() Predicate[T]`

This method negates the current predicate `p` using a logical NOT operation. The returned `Predicate` will evaluate to `true` if the original predicate `p` evaluates to `false`, and vice-versa. This is essential for defining conditions where the *absence* of a characteristic or role grants access, or to express negative constraints.

-   **Returns**: A new `Predicate[T]` that represents the logical `NOT` of `p`.

Together, these predicate composition methods provide a powerful and fluent API for constructing sophisticated authorization rules from simple boolean checks, forming the backbone of the `baccess` policy engine.

### `library.go`

This file serves as a library of re-usable `Predicate` functions, abstracting common authorization checks into convenient, generic builders. These functions significantly simplify the construction of authorization policies by providing ready-made building blocks that can be combined using the boolean logic defined in `predicate.go`.

#### Core Predicate Builders for `AccessRequest`

Most predicates in this library operate on `AccessRequest[S, R]` to evaluate conditions based on the subject, resource, or action.

-   **`func Allow[S any, R any]() Predicate[AccessRequest[S, R]]`**: Returns a `Predicate` that always evaluates to `true`, effectively granting access unconditionally.
-   **`func Deny[S any, R any]() Predicate[AccessRequest[S, R]]`**: Returns a `Predicate` that always evaluates to `false`, effectively denying access unconditionally.
-   **`func Is[S any, R any](p Predicate[AccessRequest[S, R]]) Predicate[AccessRequest[S, R]]`**: A utility function that simply returns the provided predicate.
-   **`func Not[S any, R any](p Predicate[AccessRequest[S, R]]) Predicate[AccessRequest[S, R]]`**: Returns a `Predicate` that is the logical negation of the input predicate `p`.

#### Field Comparison Predicates

These predicates compare specific fields or extracted values from the Subject and Resource of an `AccessRequest`.

-   **`func FieldEquals[S any, R any, T comparable](subjVal func(S) T, resVal func(R) T) Predicate[AccessRequest[S, R]]`**: Checks if a value extracted from the `Subject` is equal to a value extracted from the `Resource`.
-   **`func FieldNotEquals[S any, R any, T comparable](subjVal func(S) T, resVal func(R) T) Predicate[AccessRequest[S, R]]`**: Checks if a value extracted from the `Subject` is *not* equal to a value extracted from the `Resource`.
-   **`func SubjectMatches[S any, R any, T comparable](extractor func(S) T, target T) Predicate[AccessRequest[S, R]]`**: Checks if a value extracted from the `Subject` is equal to a `target` value.
-   **`func ResourceMatches[S any, R any, T comparable](extractor func(R) T, target T) Predicate[AccessRequest[S, R]]`**: Checks if a value extracted from the `Resource` is equal to a `target` value.

#### List Membership Predicates

These predicates check for membership or intersection within lists of comparable values.

-   **`func SubjectInResourceList[S any, R any, T comparable](subjVal func(S) T, resList func(R) []T) Predicate[AccessRequest[S, R]]`**: Checks if a value extracted from the `Subject` is present within a list of values extracted from the `Resource`.
-   **`func ListIntersection[S any, R any, T comparable](subjList func(S) []T, resList func(R) []T) Predicate[AccessRequest[S, R]]`**: Checks if there is any common element between a list of values extracted from the `Subject` and a list of values extracted from the `Resource`.

#### Attribute-Based Predicates (for `Attributable` subjects)

These predicates operate on subjects that implement the `Attributable` interface, allowing for dynamic attribute checks.

-   **`func SubjectAttrEquals[S Attributable, R any](key string, val any) Predicate[AccessRequest[S, R]]`**: Checks if a specific attribute (`key`) of the `Subject` is equal to a given `val`.
-   **`func SubjectAttrGT[S Attributable, R any](key string, threshold int) Predicate[AccessRequest[S, R]]`**: Checks if a specific integer attribute (`key`) of the `Subject` is *greater than* a given `threshold`.
-   **`func SubjectAttrLT[S Attributable, R any](key string, threshold int) Predicate[AccessRequest[S, R]]`**: Checks if a specific integer attribute (`key`) of the `Subject` is *less than* a given `threshold`.
-   **`func SubjectAttrTrue[S Attributable, R any](key string) Predicate[AccessRequest[S, R]]`**: Checks if a specific boolean attribute (`key`) of the `Subject` is `true`.

This `library.go` effectively transforms the raw `Predicate` type into a highly functional and expressive domain-specific language for constructing authorization policies.

### `config.go`

This file manages the configuration aspect of the `baccess` library. It defines structures for representing authorization policies in a structured format (like JSON), provides functions to load these configurations, and most importantly, integrates these configurations with the `RBAC` (Role-Based Access Control) and `Predicate` systems to build a fully functional `Evaluator`.

#### `type RolePolicyConfig struct`

Represents the policy rules for a single role.

-   **`Allow []string `json:"allow"``**: A list of strings defining what actions are permitted for this role, potentially with conditions.

#### `type Config struct`

The top-level structure for the authorization configuration.

-   **`Policies map[string]RolePolicyConfig `json:"policies"``**: A map where keys are role names and values are `RolePolicyConfig` instances.

#### `func LoadConfigFromFile(path string) (*Config, error)`

Loads authorization policies from a JSON configuration file.

#### `func LoadConfigFromMap(data map[string]any) (*Config, error)`

Loads authorization policies from a generic map.

#### `type PredicateProvider[S any, R any] interface`

An interface that allows for dynamic retrieval of named predicates.

#### `func BuildEvaluator[S RoleBearer, R any](cfg *Config, rbac *RBAC[S, R], provider PredicateProvider[S, R]) (*Evaluator[S, R], error)`

This is the central function in `config.go`, responsible for taking a loaded `Config`, an `RBAC` instance, and a `PredicateProvider`, and constructing a fully initialized `Evaluator`. It iterates through the configured policies and registers them with the `Evaluator`.
-   **Policy Rule Parsing**: Each `allowRule` (e.g., "action:condition") is parsed into an `action` and an optional `conditionName`.
-   **Predicate Resolution**: `conditionName` is used to retrieve a `Predicate` from the `PredicateProvider`. If no condition is specified, an `alwaysTrue` predicate is used.
-   **Policy Composition**: A `rolePred` (from `rbac.HasRole`) is combined with the `conditionPred` using `And()` to form a `fullPred`.
-   **Evaluator Registration**: The `fullPred` is added to the `Evaluator` under an appropriate `policyKey`.

### `registry.go`

This file provides a mechanism for registering and retrieving `Predicate` functions by a unique string name. The `Registry` acts as a central store, allowing for dynamic lookup and use of predicates, which is particularly important for integrating with declarative policy configurations where predicates are often referenced by name.

#### `type Registry[S any, R any] struct`

A generic struct that holds a collection of `Predicate` functions, mapped by their names.

#### `func NewRegistry[S any, R any]() *Registry[S, R]`

Creates and returns a new, empty `Registry` instance.

#### `func (r *Registry[S, R]) Register(name string, p Predicate[AccessRequest[S, R]])`

Registers a `Predicate` function with the registry under a given `name`. Overwrites if `name` already exists.

#### `func (r *Registry[S, R]) GetPredicate(name string) (Predicate[AccessRequest[S, R]], error)`

Retrieves a `Predicate` function from the registry by its `name`. Implements the `PredicateProvider` interface.

### `evaluator.go`

This file defines the `Evaluator` component, which is central to the `baccess` authorization system. The `Evaluator` is responsible for storing compiled authorization policies (as `Predicate` functions) and, given an `AccessRequest`, determining if any of the registered policies grant access.

#### `type Evaluator[S any, R any] struct`

Holds a collection of policies (predicates) mapped by action strings.

#### `func NewEvaluator[S any, R any]() *Evaluator[S, R]`

Creates and returns a new, empty `Evaluator` instance.

#### `func (e *Evaluator[S, R]) AddPolicy(action string, p Predicate[AccessRequest[S, R]])`

Registers a new policy. If a policy for the `action` exists, `p` is combined with it using logical `OR`.

#### `func (e *Evaluator[S, R]) Evaluate(req AccessRequest[S, R]) bool`

The core method for making authorization decisions.
-   **Policy Matching Rules**: Iterates through registered policies and matches them against `req.Action` based on several rules: global wildcard `*`, exact match, action-level wildcard (`action:*`), and implicit matches between base actions and conditioned actions.
-   **Combine Matching Predicates**: All matching predicates are combined using a logical `OR`.
-   **Final Evaluation**: The combined predicate is evaluated against the `AccessRequest`. If no policies match, access is implicitly denied.

### `rbac.go`

This file implements core functionalities for Role-Based Access Control (RBAC) within the `baccess` system. It provides predicate builders to check if a subject possesses specific roles, thereby enabling policy decisions based on a subject's assigned roles.

#### `func HasRole[S RoleBearer, R any](role string) Predicate[AccessRequest[S, R]]`

Creates a `Predicate` that evaluates to `true` if the subject has the exact `role`.

#### `func HasAnyRole[S RoleBearer, R any](targetRoles ...string) Predicate[AccessRequest[S, R]]`

Creates a `Predicate` that evaluates to `true` if the subject possesses *any* of the `targetRoles`.

#### `type RBAC[S RoleBearer, R any] struct`

A generic type acting as a container for RBAC-related operations.

#### `func NewRBAC[S RoleBearer, R any]() *RBAC[S, R]`

Creates and returns a new, empty `RBAC` instance.

#### `func (rbac *RBAC[S, R]) HasRole(targetRole string) Predicate[AccessRequest[S, R]]`

Receiver method version of `HasRole`.

#### `func (rbac *RBAC[S, R]) HasAnyRole(targetRoles ...string) Predicate[AccessRequest[S, R]]`

Receiver method version of `HasAnyRole`.

### `cmd/main.go` (Example Usage)

This file provides a concrete, executable example of how to utilize the `baccess` library for implementing predicate-based access control. It defines sample `User` and `Document` types (implementing `baccess` interfaces), registers custom predicates, loads a policy configuration, builds an `Evaluator`, and then performs various access checks to illustrate different authorization scenarios.

-   **Custom Types**: `User` (implements `RoleBearer`, `Identifiable`, `Attributable`) and `Document`.
-   **Configuration**: Loads from `config.json` or an in-memory map.
-   **Predicate Registration**: Registers `isOwner`, `isCollaborator`, `isPublic` predicates with `baccess.Registry`.
-   **Evaluation Flow**: Demonstrates building the `Evaluator` using `baccess.BuildEvaluator` and then evaluating various `AccessRequest`s to show access control in action. This includes examples of role-based access, attribute-based access, and conditional policies.

## 4. Performance Analysis of Predicate-Based Authorization

### 1. Introduction
This document summarizes the performance characteristics of the Go predicate-based authorization package, focusing on the efficiency of policy evaluation for both simple and complex access control scenarios. Performance tests were conducted to measure execution time, memory allocations, and overall throughput.

### 2. Methodology
Go's built-in benchmarking tools were utilized to execute performance tests. The benchmarks were run with specific flags to provide comprehensive metrics:
- `-bench=.`: Runs all benchmarks in the specified package.
- `-benchmem`: Enables memory allocation profiling, reporting bytes allocated per operation (`B/op`) and number of allocations per operation (`allocs/op`).
- `-benchtime=100000000x`: Forces each benchmark to run exactly 100,000,000 iterations, ensuring highly stable and reproducible `ns/op` (nanoseconds per operation) measurements.

### 3. Test Environment
- My personal laptop was used for testing, with the following specifications:
- **Operating System:** macOS (Tahoe 26.2)
- **Architecture:** `arm64` (Apple Silicon)
- **CPU:** Apple M3 Pro

### 4. Key Metrics Explained
- **`ns/op` (Nanoseconds per Operation):** The average time taken (in nanoseconds) to complete a single policy evaluation. Lower values indicate faster execution.
- **`B/op` (Bytes allocated per Operation):** The average number of bytes allocated on the heap during a single operation. Lower values indicate better memory efficiency and reduced garbage collection overhead.
- **`allocs/op` (Allocations per Operation):** The average number of distinct memory allocations performed during a single operation. Lower values indicate better memory efficiency and reduced garbage collection overhead.

### 5. Summary of Results

The following benchmark results were obtained:

```bash
goos: darwin
goarch: arm64
pkg: github.com/brian-nunez/baccess/perf
cpu: Apple M3 Pro
BenchmarkPolicyEvaluation/ReadAccess_SimpleAllow-12                                     100000000               119.2 ns/op           32 B/op             1 allocs/op
BenchmarkPolicyEvaluation/DeleteAccess_Owner_True-12                                    100000000               94.42 ns/op            0 B/op             0 allocs/op
BenchmarkPolicyEvaluation/DeleteAccess_Owner_False-12                                   100000000               95.30 ns/op            0 B/op             0 allocs/op
BenchmarkPolicyEvaluation/UpdateAccess_OwnerOrCollaborator_OwnerTrue-12                 100000000               96.04 ns/op            0 B/op             0 allocs/op
BenchmarkPolicyEvaluation/UpdateAccess_OwnerOrCollaborator_CollaboratorTrue-12          100000000               95.79 ns/op            0 B/op             0 allocs/op
BenchmarkPolicyEvaluation/UpdateAccess_OwnerOrCollaborator_False-12                     100000000               97.38 ns/op            0 B/op             0 allocs/op
BenchmarkPolicyEvaluation/ArchiveAccess_NotOwner_True-12                                100000000               96.59 ns/op            0 B/op             0 allocs/op
BenchmarkPolicyEvaluation/ArchiveAccess_NotOwner_False-12                               100000000               96.25 ns/op            0 B/op             0 allocs/op
BenchmarkPolicyEvaluation/PublishAccess_OwnerAndDraft_True-12                           100000000               96.71 ns/op            0 B/op             0 allocs/op
BenchmarkPolicyEvaluation/PublishAccess_OwnerAndDraft_False_NotOwner-12                 100000000               96.95 ns/op            0 B/op             0 allocs/op
BenchmarkPolicyEvaluation/PublishAccess_OwnerAndDraft_False_NotDraft-12                 100000000               97.78 ns/op            0 B/op             0 allocs/op
BenchmarkPolicyEvaluation/CommentAccess_DepartmentMember_True-12                        100000000               96.06 ns/op            0 B/op             0 allocs/op
BenchmarkPolicyEvaluation/CommentAccess_DepartmentMember_False-12                       100000000               97.49 ns/op            0 B/op             0 allocs/op
BenchmarkPolicyEvaluation/AdminAccess_WildcardAction-12                                 100000000               96.63 ns/op            0 B/op             0 allocs/op
PASS
ok      github.com/brian-nunez/baccess/perf    137.654s
```

### 6. Analysis

#### Execution Time (`ns/op`)
- **Consistent High Speed:** Policy evaluations are consistently performed within a very tight range. Most complex scenarios average between **94 ns/op and 98 ns/op**.
- **Minimal Overhead for Complexity:** The overhead introduced by combining multiple predicates using `And()`, `Or()`, and `Not()` methods is remarkably low. The `ns/op` for composite predicates (e.g., `UpdateAccess`, `PublishAccess`) remains almost identical to simpler single-predicate checks (e.g., `DeleteAccess`).
- **`ReadAccess_SimpleAllow`:** This scenario, which tests a basic `read:*` policy, shows `119.2 ns/op`. While slightly higher than other benchmarks, this is still extremely fast. The difference compared to simpler single-predicate checks might stem from the mock object's structure and method calls involved in its setup, even if the policy itself is simple.
- **`AdminAccess_WildcardAction`:** This benchmark, which relies on a superuser wildcard, demonstrates similar efficiency (`96.63 ns/op`), indicating effective short-circuiting where applicable.

#### Memory Efficiency (`B/op` and `allocs/op`)
- **Outstanding Zero Allocations:** For all complex policy evaluations except `ReadAccess_SimpleAllow`, the system achieves **0 B/op and 0 allocs/op**. This is an exceptional result, meaning that once the policy evaluator is built, its runtime evaluation involves no heap memory allocations. This virtually eliminates garbage collection pauses, which is critical for high-performance and low-latency applications.
- **Minor Allocation in `ReadAccess_SimpleAllow`:** This benchmark shows `32 B/op` and `1 allocs/op`. This minor allocation is likely attributable to specific internal handling for very generic wildcard rules or how initial data might be buffered/copied, but it remains a very small footprint.

## 7. Conclusion
The Go predicate-based authorization package demonstrates **excellent performance and outstanding memory efficiency**.
- Policy evaluations are consistently achieved in **under 100 nanoseconds** for complex scenarios, allowing for millions of authorization checks per second on modern hardware.
- Critically, the system performs **zero heap memory allocations** during the evaluation of most complex policies. This characteristic is highly desirable for applications requiring high throughput, low latency, and predictable performance, as it minimizes the impact of garbage collection.

The design effectively leverages the "Predicate Pattern" to build sophisticated access control rules without sacrificing performance. This makes it a robust and scalable solution for authorization.
