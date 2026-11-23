# 32. Scheduling class and QoS authority

| | |
| --- | --- |
| Route | lifecycle |
| Current owner | [Runtime scheduling class](../architecture/runtime-authority.md#scheduling-class) |
| Related exploration | [Resource accounts](25-resource-accounts.md), [energy accounting](17-energy-accounting.md), and [foreign workloads](../plans/foreign-workloads.md) |

## Open questions

- Does a container or guest receive one class for the whole workload, or may
  it subdivide internally without widening its granted authority?
- Is a general supervision-subtree class policy needed beyond the current
  instance assignments and spawner-to-child promotion edges? Define inheritance
  and restart behavior before claiming such a policy.
- Does the mixed-workload product need share weights or explicit latency targets
  beyond class ordering? Any quantity guarantee must satisfy the MCS proposal's
  admission and accounting requirements rather than treating priority as a budget.
