# Configuration File (`config.json`)

`Baccess` can be configured entirely in Go, but for greater flexibility, it supports loading policies from a JSON file. This allows you to modify your authorization rules without recompiling your application.

This document details the structure and syntax of the `config.json` file.

## High-Level Structure

The configuration file is a JSON object with a single top-level key: `policies`.

```json
{
  "policies": {
    "admin": {
      "allow": ["*"]
    },
    "editor": {
      "allow": [
        "read:*",
        "delete:isOwner"
      ]
    }
  }
}
```

*   **`policies`**: This is a JSON object where each key represents a **Role** in your system (e.g., `"admin"`, `"editor"`, `"viewer"`).
*   **Role Object (`"admin"`, `"editor"`)**: Each role object contains keys that define the permissions for that role. Currently, `Baccess` supports `allow`.
*   **`allow`**: This is an array of strings, where each string is a **Rule** that grants permission.

## The `allow` Array and Rule Syntax

Each string in the `allow` array defines a permission. A rule grants access to a specific **Action** if a specific **Condition** is met. The syntax for a rule is a string in one of the following formats:

1.  **`"action"`** (e.g., `"delete"`)
2.  **`"action:condition"`** (e.g., `"delete:isOwner"`)
3.  **`"action:*"`** (e.g., `"read:*"`)
4.  **`"*"`** (Global Wildcard)

Let's break down each format.

### 1. Simple Action: `"action"`

This format grants permission for the specified action, with the condition implicitly being "always true".

**Example:**
```json
"allow": ["read"]
```
This is functionally equivalent to `"read:*"`. It means a user with this role can always perform the `"read"` action, regardless of any other attributes of the user or resource.

### 2. Action with Condition: `"action:condition"`

This is the most common format for Attribute-Based Access Control (ABAC). It grants permission for the `action` *only if* the named `condition` predicate returns `true`.

**Example:**
```json
"allow": ["delete:isOwner"]
```
*   **Action:** `delete`
*   **Condition:** `isOwner`

When the system evaluates this rule, it looks up the predicate registered with the name `"isOwner"` in the `Registry`. If that predicate returns `true`, this part of the policy is satisfied.

**Important:** The `condition` name must correspond to a predicate you have registered in your `auth.Registry` instance. If the predicate is not found, `Baccess` will return an error during evaluator setup, and the rule will default to `Deny`.

### 3. Action with Wildcard Condition: `"action:*"`

This format explicitly grants permission for an `action` under all circumstances. The `*` wildcard for the condition means "always true".

**Example:**
```json
"allow": ["read:*"]
```
This grants permission for the `"read"` action. When the policy is being evaluated for a `"read"` request, this rule will always satisfy its condition part.

This syntax also supports **action-prefix matching**. A policy for `"read:*"` will match *any* requested action that starts with `"read:"`. For example, requests for `"read:summary"`, `"read:full"`, or `"read:metadata"` would all be matched by a `"read:*"` policy.

### 4. Global Wildcard: `"*"`

A single `*` in the `allow` array is a global wildcard. It grants permission for **any action**. This is typically reserved for superuser or administrator roles.

**Example:**
```json
"policies": {
  "admin": {
    "allow": ["*"]
  }
}
```
A user with the `"admin"` role can perform any action (`"read"`, `"delete"`, `"nuke"`, `"any:thing"`, etc.) without any further conditions.

## How Rules are Combined

*   **Rules for the same Role:** All `allow` rules for a given role are effectively **OR**-ed together. A user gains access if they have the role and *any* of the rules for that role grant permission for the requested action.

*   **Rules for the same Action:** If a role has multiple rules for the same action, they are also **OR**-ed.
    ```json
    "allow": [
      "edit:isOwner",
      "edit:isCollaborator"
    ]
    ```
    In this case, a user with this role can `"edit"` if they are the owner **OR** if they are a collaborator.

This flexible rule syntax allows you to define a wide range of authorization policies, from simple role-based permissions to complex, attribute-based decisions, all within a single, easy-to-read JSON file.