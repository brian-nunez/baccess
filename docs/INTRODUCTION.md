# Introduction to Baccess

`Baccess` is a flexible, predicate-based authorization library for Go, designed to facilitate both Role-Based Access Control (RBAC) and Attribute-Based Access Control (ABAC) with a highly readable and composable API.

## Core Philosophy

The central philosophy of `Baccess` is that all authorization decisions can be distilled into a series of boolean questions. These questions are represented as **Predicates**, which are simply functions that take an `AccessRequest` and return `true` or `false`.

- **Predicate:** A function of the form `f(x) -> bool`. In `Baccess`, this is `Predicate[AccessRequest]`.

By representing authorization logic as predicates, we can create a powerful and expressive system where complex policies are built by composing simpler ones using logical combinators.

## Key Features

*   **Predicate-Based Logic:** Represent any authorization rule as a function that returns a boolean. This makes policies easy to test, understand, and reuse.
*   **Composable Policies:** Combine simple predicates using `And()`, `Or()`, and `Not()` methods to build sophisticated, layered authorization logic.
*   **Hybrid RBAC & ABAC:** The system seamlessly blends Role-Based Access Control (e.g., "is the user an admin?") and Attribute-Based Access Control (e.g., "is the document's status 'published'?") within the same policy framework.
*   **Dynamic Configuration:** Define your policies in Go code for compile-time safety and performance, or load them dynamically from a JSON configuration file for maximum flexibility and runtime updates without recompiling.
*   **Extensible Predicate Library:** `Baccess` provides a rich library of common, reusable predicates (e.g., `FieldEquals`, `ListIntersection`, `SubjectAttrEquals`) while making it trivial to register your own custom business logic as new predicates.
*   **Advanced Wildcard Matching:** The policy evaluator supports multiple levels of wildcards for actions, including global (`*`) and action-prefix (`action:*`) matching, providing fine-grained control over permissions.

## How It Works: A High-Level View

1.  **The Access Request:** When a user (the **Subject**) attempts to perform an **Action** on a **Resource**, the application creates an `AccessRequest` object. This object encapsulates all the information needed to make an authorization decision.

2.  **Policy Evaluation:** The `AccessRequest` is passed to the `Evaluator`. The `Evaluator` holds a map of `Actions` to `Predicates`.

3.  **Predicate Matching:** The `Evaluator` finds the appropriate `Predicate` (or combination of `Predicates`) that matches the requested `Action`, including handling wildcards.

4.  **Decision:** The matched `Predicate` is executed with the `AccessRequest`. If it returns `true`, access is granted. If it returns `false`, access is denied.

This approach provides a clear and decoupled way to manage authorization logic, separating it from your core application code.
