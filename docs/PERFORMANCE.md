# Performance Analysis of Predicate-Based Authorization

## 1. Introduction
This document summarizes the performance characteristics of the Go predicate-based authorization package, focusing on the efficiency of policy evaluation for both simple and complex access control scenarios. Performance tests were conducted to measure execution time, memory allocations, and overall throughput.

## 2. Methodology
Go's built-in benchmarking tools were utilized to execute performance tests. The benchmarks were run with specific flags to provide comprehensive metrics:
- `-bench=.`: Runs all benchmarks in the specified package.
- `-benchmem`: Enables memory allocation profiling, reporting bytes allocated per operation (`B/op`) and number of allocations per operation (`allocs/op`).
- `-benchtime=100000000x`: Forces each benchmark to run exactly 100,000,000 iterations, ensuring highly stable and reproducible `ns/op` (nanoseconds per operation) measurements.

## 3. Test Environment
- My personal laptop was used for testing, with the following specifications:
- **Operating System:** macOS (Tahoe 26.2)
- **Architecture:** `arm64` (Apple Silicon)
- **CPU:** Apple M3 Pro

## 4. Key Metrics Explained
- **`ns/op` (Nanoseconds per Operation):** The average time taken (in nanoseconds) to complete a single policy evaluation. Lower values indicate faster execution.
- **`B/op` (Bytes allocated per Operation):** The average number of bytes allocated on the heap during a single operation. Lower values indicate better memory efficiency and reduced garbage collection overhead.
- **`allocs/op` (Allocations per Operation):** The average number of distinct memory allocations performed during a single operation. Lower values indicate better memory efficiency and reduced garbage collection overhead.

## 5. Summary of Results

The following benchmark results were obtained:

```bash
goos: darwin

goarch: arm64
pkg: github.com/brian-nunez/baccess/v1/perf
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
ok      github.com/brian-nunez/baccess/v1/perf    137.654s
```

## 6. Analysis

### Execution Time (`ns/op`)
- **Consistent High Speed:** Policy evaluations are consistently performed within a very tight range. Most complex scenarios average between **94 ns/op and 98 ns/op**.
- **Minimal Overhead for Complexity:** The overhead introduced by combining multiple predicates using `And()`, `Or()`, and `Not()` methods is remarkably low. The `ns/op` for composite predicates (e.g., `UpdateAccess`, `PublishAccess`) remains almost identical to simpler single-predicate checks (e.g., `DeleteAccess`).
- **`ReadAccess_SimpleAllow`:** This scenario, which tests a basic `read:*` policy, shows `119.2 ns/op`. While slightly higher than other benchmarks, this is still extremely fast. The difference compared to simpler single-predicate checks might stem from the mock object's structure and method calls involved in its setup, even if the policy itself is simple.
- **`AdminAccess_WildcardAction`:** This benchmark, which relies on a superuser wildcard, demonstrates similar efficiency (`96.63 ns/op`), indicating effective short-circuiting where applicable.

### Memory Efficiency (`B/op` and `allocs/op`)
- **Outstanding Zero Allocations:** For all complex policy evaluations except `ReadAccess_SimpleAllow`, the system achieves **0 B/op and 0 allocs/op**. This is an exceptional result, meaning that once the policy evaluator is built, its runtime evaluation involves no heap memory allocations. This virtually eliminates garbage collection pauses, which is critical for high-performance and low-latency applications.
- **Minor Allocation in `ReadAccess_SimpleAllow`:** This benchmark shows `32 B/op` and `1 allocs/op`. This minor allocation is likely attributable to specific internal handling for very generic wildcard rules or how initial data might be buffered/copied, but it remains a very small footprint.

## 7. Conclusion
The Go predicate-based authorization package demonstrates **excellent performance and outstanding memory efficiency**.
- Policy evaluations are consistently achieved in **under 100 nanoseconds** for complex scenarios, allowing for millions of authorization checks per second on modern hardware.
- Critically, the system performs **zero heap memory allocations** during the evaluation of most complex policies. This characteristic is highly desirable for applications requiring high throughput, low latency, and predictable performance, as it minimizes the impact of garbage collection.

The design effectively leverages the "Predicate Pattern" to build sophisticated access control rules without sacrificing performance. This makes it a robust and scalable solution for authorization.
