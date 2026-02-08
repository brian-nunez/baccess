# Policy Evaluation

The `auth.Evaluator` is the engine at the heart of `Baccess`. It is responsible for storing policies and evaluating an `auth.AccessRequest` to render a final `true` or `false` decision.

This document explains the two main parts of the evaluator's lifecycle: adding policies and evaluating requests.

## 1. Adding Policies

Policies are added to the evaluator using the `AddPolicy(action string, p predicates.Predicate[AccessRequest[S, R]])` method.

*   `action`: A string that serves as the key for the policy. This key is what the evaluator matches against the `Action` field of an incoming `AccessRequest`. The key can be a simple action (`"edit"`), an action with a condition (`"edit:isOwner"`), or a wildcard (`"edit:*"`, `"*"`).
*   `p`: The predicate that will be evaluated if the policy key matches the request.

### Policy Composition for a Single Action

If you call `AddPolicy` multiple times with the same `action` key, the `Evaluator` does not overwrite the old policy. Instead, it automatically combines the existing predicate with the new one using an **`Or`** operation.

**Example:**

Consider the following setup from `pkg/config/loader.go`:
```json
"allow": [
  "edit:isOwner",
  "edit:isCollaborator"
]
```
The loader will process this by calling `AddPolicy` twice:
1.  `evaluator.AddPolicy("edit:isOwner", isOwnerPredicate)`
2.  `evaluator.AddPolicy("edit:isCollaborator", isCollaboratorPredicate)`

This is straightforward because the keys are different. However, if multiple roles grant the same permission, the `Or` logic becomes crucial.

**Example 2: Multiple Roles Granting the Same Permission**
```go
// From config...
// Role "editor" gets "edit" permission
// Role "admin" gets "edit" permission

// The loader would generate and add these policies:
evaluator.AddPolicy("edit", rbac.HasRole("editor"))

// When the second policy for "edit" is added:
evaluator.AddPolicy("edit", rbac.HasRole("admin"))

// The evaluator's internal state for the "edit" policy becomes:
// rbac.HasRole("editor").Or(rbac.HasRole("admin"))
```
This powerful feature means that access is granted if *any* of the conditions for a given action are met, which is the intuitive behavior for most authorization systems.

## 2. The Evaluation Process

When you call `evaluator.Evaluate(req)`, a sophisticated matching process begins to find all policies that could potentially apply to the `req.Action`.

The `Evaluator` iterates through all of its registered policy keys and collects any that match the `req.Action` based on a set of rules. All matching predicates are then combined with `Or` to produce the final result.

Here are the matching rules, in the order they are checked internally:

### Rule 1: Exact Match

The `Evaluator` first looks for a policy key that is an exact match for the `req.Action`.

*   **If `req.Action` is `"edit"`**: The evaluator looks for a policy registered with the key `"edit"`.
*   **If `req.Action` is `"edit:isOwner"`**: The evaluator looks for a policy registered with the key `"edit:isOwner"`.

### Rule 2: Global Wildcard Match (`*`)

The `Evaluator` checks if a policy is registered with the key `"*"`. If so, this policy is always considered a match for any action. This is the "superuser" or "admin" bypass.

### Rule 3: Action-Prefix Wildcard Match (`action:*`)

The `Evaluator` checks if the requested action matches a registered action-prefix wildcard policy.

This rule applies when:
*   The policy key is in the format `"action:*"`.
*   The `req.Action` starts with the same `"action:"` prefix.

**Example:**
*   A policy registered for `"read:*"` will match a `req.Action` of `"read:summary"`.
*   A policy registered for `"edit:*"` will match a `req.Action` of `"edit:title"`.

### Rule 4: Action with Condition Match

The `Evaluator` checks if the requested action (which must be a simple action without a `:`) matches the base part of a policy key that has a condition.

This rule applies when:
*   The policy key is in the format `"action:condition"` (e.g., `"edit:isOwner"`).
*   The `req.Action` is *exactly* the `action` part (e.g., `"edit"`).

This ensures that when a user requests a general action like `"edit"`, all specific edit-related policies (like `"edit:isOwner"`, `"edit:isCollaborator"`) are evaluated to see if the user satisfies *any* of them.

### Final Decision

1.  The `Evaluator` gathers all predicates from all matching policies found using the rules above.
2.  If no matching policies are found, the result is `false`.
3.  If one or more matching policies are found, their predicates are combined into a single, large predicate using `Or`.
4.  This final combined predicate is executed. If it returns `true`, access is granted. Otherwise, it is denied.

This comprehensive evaluation logic ensures that policies are applied intuitively, whether they are broad role-based rules, specific attribute-based rules, or wide-reaching wildcards.
