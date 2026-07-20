# Standard Library: Algorithms and Data Structures

Status: active reference for algorithm-related builtins.

## Core Collections
- `set_new`, `set_add`, `set_contains`
- `queue_new`, `queue_push`, `queue_pop`
- `stack_new`, `stack_push`, `stack_pop`
- `pq_new`, `pq_push`, `pq_pop_min`

## Disjoint Set / Range Structures
- `dsu_new`, `dsu_find`, `dsu_union`
- `segtree_new`, `segtree_update`, `segtree_query`
- `segtree_lazy_new`, `segtree_lazy_add`, `segtree_lazy_query`
- `segtree_dynamic_new`, `segtree_dynamic_add`, `segtree_dynamic_query`
- `sparse_table_new`, `sparse_table_query`
- `lichao_new`, `lichao_add`, `lichao_query`

## Graph Algorithms
- `graph_new`, `graph_add_edge`, `graph_neighbors`
- `graph_bfs`, `graph_dijkstra`, `graph_astar`, `graph_dials`, `graph_zero_one_bfs`
- `graph_floyd_warshall`, `graph_scc`, `graph_toposort`
- `graph_bridges`, `graph_articulation_points`

## String / Sequence Algorithms
- `kmp_search`, `z_function`, `manacher_lps`, `suffix_array`
- `rabin_karp`, `rolling_hash_table`, `rolling_hash_sub`
- `window_sum_fixed`, `window_min`, `window_max`

## Math / Number Theory
- `gcd`, `lcm`, `pow_mod`, `is_prime`, `sieve`
- `pollard_rho`
- `fft_convolve`, `ntt_convolve`

## Classic DP / Search Helpers
- `lis_length`, `knapsack_01`
- `lower_bound`, `upper_bound`
- `list_range`

## Test Coverage
The crate includes dedicated tests for algorithm and graph behavior:
- `naux-lang/tests/algo_std.rs`
- `naux-lang/tests/graph_algo.rs`
- `naux-lang/tests/sparse_table_tests.rs`

## Source of Builtin Registration
Builtin names are registered in `naux-lang/src/stdlib/` modules via `env.set_builtin(...)`.
