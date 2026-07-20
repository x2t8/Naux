#![allow(
    clippy::get_first,
    clippy::manual_unwrap_or,
    clippy::too_many_arguments,
    clippy::needless_range_loop
)]

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};

use crate::runtime::env::Env;
use crate::runtime::error::RuntimeError;
use crate::runtime::value::{Graph, NauxObj, Value};

pub fn register_graph(env: &mut Env) {
    env.set_builtin("graph_new", graph_new);
    env.set_builtin("graph_add_edge", graph_add_edge);
    env.set_builtin("graph_neighbors", graph_neighbors);
    env.set_builtin("graph_bfs", graph_bfs);
    env.set_builtin("graph_dijkstra", graph_dijkstra);
    env.set_builtin("graph_zero_one_bfs", graph_zero_one_bfs);
    env.set_builtin("graph_dials", graph_dials);
    env.set_builtin("graph_astar", graph_astar);
    env.set_builtin("graph_bridges", graph_bridges);
    env.set_builtin("graph_articulation_points", graph_articulation_points);
    env.set_builtin("graph_scc", graph_scc_tarjan);
    env.set_builtin("graph_toposort", graph_toposort);
    env.set_builtin("graph_floyd_warshall", graph_floyd_warshall);
}

fn graph_new(args: Vec<Value>) -> Result<Value, RuntimeError> {
    let directed = matches!(args.get(0), Some(Value::Bool(true)));
    let g = Graph {
        directed,
        adj: HashMap::new(),
    };
    Ok(Value::make_graph(g))
}

fn graph_add_edge(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() < 3 {
        return Err(RuntimeError::new(
            "graph_add_edge requires at least 3 args: (graph, from, to, [weight])",
            None,
        ));
    }
    let g = match &args[0] {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Graph(g) => g,
            _ => {
                return Err(RuntimeError::new(
                    "graph_add_edge: first argument must be a Graph",
                    None,
                ))
            }
        },
        _ => {
            return Err(RuntimeError::new(
                "graph_add_edge: first argument must be a Graph",
                None,
            ))
        }
    };
    let from = args[1]
        .as_text()
        .ok_or_else(|| RuntimeError::new("graph_add_edge: from must be text", None))?;
    let to = args[2]
        .as_text()
        .ok_or_else(|| RuntimeError::new("graph_add_edge: to must be text", None))?;
    let weight = match args.get(3).and_then(|v| v.as_f64()) {
        Some(n) => n,
        None => 1.0,
    };

    {
        let mut graph = g.borrow_mut();
        graph
            .adj
            .entry(from.clone())
            .or_insert_with(Vec::new)
            .push((to.clone(), weight));
        if !graph.directed {
            graph
                .adj
                .entry(to)
                .or_insert_with(Vec::new)
                .push((from, weight));
        }
    }
    Ok(Value::Null)
}

fn graph_neighbors(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new(
            "graph_neighbors(graph, node) requires 2 args",
            None,
        ));
    }
    let g = match &args[0] {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Graph(g) => g,
            _ => {
                return Err(RuntimeError::new(
                    "graph_neighbors: first arg must be Graph",
                    None,
                ))
            }
        },
        _ => {
            return Err(RuntimeError::new(
                "graph_neighbors: first arg must be Graph",
                None,
            ))
        }
    };
    let node = args[1]
        .as_text()
        .ok_or_else(|| RuntimeError::new("graph_neighbors: node must be text", None))?;
    let graph = g.borrow();
    let neigh = graph
        .adj
        .get(&node)
        .map(|v| {
            v.iter()
                .map(|(n, _)| Value::make_text(n.clone()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(Vec::new);
    Ok(Value::make_list(neigh))
}

fn graph_bfs(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new(
            "graph_bfs(graph, start) requires 2 args",
            None,
        ));
    }
    let g = match &args[0] {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Graph(g) => g,
            _ => {
                return Err(RuntimeError::new(
                    "graph_bfs: first arg must be Graph",
                    None,
                ))
            }
        },
        _ => {
            return Err(RuntimeError::new(
                "graph_bfs: first arg must be Graph",
                None,
            ))
        }
    };
    let start = args[1]
        .as_text()
        .ok_or_else(|| RuntimeError::new("graph_bfs: start must be text", None))?;

    let graph = g.borrow();
    let mut visited = HashSet::new();
    let mut order = Vec::new();
    let mut q = VecDeque::new();

    visited.insert(start.clone());
    q.push_back(start.clone());

    while let Some(node) = q.pop_front() {
        order.push(Value::make_text(node.clone()));
        if let Some(neigh) = graph.adj.get(&node) {
            for (nbr, _) in neigh {
                if visited.insert(nbr.clone()) {
                    q.push_back(nbr.clone());
                }
            }
        }
    }

    Ok(Value::make_list(order))
}

fn graph_dijkstra(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() < 3 {
        return Err(RuntimeError::new(
            "graph_dijkstra(graph, source, target)",
            None,
        ));
    }
    let g = match &args[0] {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Graph(g) => g,
            _ => {
                return Err(RuntimeError::new(
                    "graph_dijkstra: first arg must be Graph",
                    None,
                ))
            }
        },
        _ => {
            return Err(RuntimeError::new(
                "graph_dijkstra: first arg must be Graph",
                None,
            ))
        }
    };
    let source = args[1]
        .as_text()
        .ok_or_else(|| RuntimeError::new("graph_dijkstra: source must be text", None))?;
    let target = args[2]
        .as_text()
        .ok_or_else(|| RuntimeError::new("graph_dijkstra: target must be text", None))?;

    #[derive(Clone)]
    struct State {
        cost: f64,
        node: String,
    }
    impl Eq for State {}
    impl PartialEq for State {
        fn eq(&self, other: &Self) -> bool {
            self.cost == other.cost && self.node == other.node
        }
    }
    impl Ord for State {
        fn cmp(&self, other: &Self) -> Ordering {
            // reverse for min-heap behavior
            other
                .cost
                .partial_cmp(&self.cost)
                .unwrap_or(Ordering::Equal)
        }
    }
    impl PartialOrd for State {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    let graph = g.borrow();
    let mut dist: HashMap<String, f64> = HashMap::new();
    let mut prev: HashMap<String, String> = HashMap::new();
    for n in graph.adj.keys() {
        dist.insert(n.clone(), f64::INFINITY);
    }
    dist.insert(source.clone(), 0.0);

    let mut heap = BinaryHeap::new();
    heap.push(State {
        cost: 0.0,
        node: source.clone(),
    });

    while let Some(State { cost, node }) = heap.pop() {
        if cost > *dist.get(&node).unwrap_or(&f64::INFINITY) {
            continue;
        }
        if let Some(neigh) = graph.adj.get(&node) {
            for (nbr, w) in neigh {
                let next = cost + *w;
                if next < *dist.get(nbr).unwrap_or(&f64::INFINITY) {
                    dist.insert(nbr.clone(), next);
                    prev.insert(nbr.clone(), node.clone());
                    heap.push(State {
                        cost: next,
                        node: nbr.clone(),
                    });
                }
            }
        }
    }

    if !dist.contains_key(&target) || dist[&target].is_infinite() {
        return Ok(Value::Null);
    }

    let mut path_nodes = Vec::new();
    let mut cur = target.clone();
    path_nodes.push(Value::make_text(cur.clone()));
    while let Some(p) = prev.get(&cur) {
        cur = p.clone();
        path_nodes.push(Value::make_text(cur.clone()));
    }
    path_nodes.reverse();

    let dist_val = dist.get(&target).cloned().unwrap_or(f64::INFINITY);
    let mut map = std::collections::HashMap::new();
    map.insert("distance".into(), Value::Float(dist_val));
    map.insert("path".into(), Value::make_list(path_nodes));
    Ok(Value::make_map(map))
}

fn graph_astar(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() < 3 {
        return Err(RuntimeError::new(
            "graph_astar(graph, start, goal, [heuristic_map])",
            None,
        ));
    }
    let g = match &args[0] {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Graph(gr) => gr.clone(),
            _ => {
                return Err(RuntimeError::new(
                    "graph_astar: first arg must be Graph",
                    None,
                ))
            }
        },
        _ => {
            return Err(RuntimeError::new(
                "graph_astar: first arg must be Graph",
                None,
            ))
        }
    };
    let start = args[1]
        .as_text()
        .ok_or_else(|| RuntimeError::new("graph_astar: start must be text", None))?;
    let goal = args[2]
        .as_text()
        .ok_or_else(|| RuntimeError::new("graph_astar: goal must be text", None))?;
    let heur_map = args.get(3).and_then(|v| match v {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Map(m) => Some(m.clone()),
            _ => None,
        },
        _ => None,
    });

    #[derive(Clone)]
    struct State {
        f: f64,
        g: f64,
        node: String,
    }
    impl Eq for State {}
    impl PartialEq for State {
        fn eq(&self, other: &Self) -> bool {
            self.f == other.f && self.node == other.node
        }
    }
    impl Ord for State {
        fn cmp(&self, other: &Self) -> Ordering {
            other
                .f
                .partial_cmp(&self.f)
                .unwrap_or(Ordering::Equal)
                .then_with(|| self.node.cmp(&other.node))
        }
    }
    impl PartialOrd for State {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    let graph = g.borrow();
    let mut open = BinaryHeap::new();
    let mut g_score: HashMap<String, f64> = HashMap::new();
    let mut came_from: HashMap<String, String> = HashMap::new();

    let h_start = heur_map
        .as_ref()
        .and_then(|m| m.borrow().get(&goal).and_then(|v| v.as_f64()))
        .unwrap_or(0.0);
    g_score.insert(start.clone(), 0.0);
    open.push(State {
        f: h_start,
        g: 0.0,
        node: start.clone(),
    });

    let heuristic = |n: &str| -> f64 {
        heur_map
            .as_ref()
            .and_then(|m| m.borrow().get(n).and_then(|v| v.as_f64()))
            .unwrap_or(0.0)
    };

    while let Some(State { f: _, g, node }) = open.pop() {
        if node == goal {
            let mut path_nodes = Vec::new();
            let mut cur = goal.clone();
            path_nodes.push(Value::make_text(cur.clone()));
            while let Some(p) = came_from.get(&cur) {
                cur = p.clone();
                path_nodes.push(Value::make_text(cur.clone()));
            }
            path_nodes.reverse();
            let mut map = HashMap::new();
            map.insert("distance".into(), Value::Float(g));
            map.insert("path".into(), Value::make_list(path_nodes));
            return Ok(Value::make_map(map));
        }
        if g > *g_score.get(&node).unwrap_or(&f64::INFINITY) {
            continue;
        }
        if let Some(nei) = graph.adj.get(&node) {
            for (nbr, w) in nei {
                let tentative = g + *w;
                if tentative < *g_score.get(nbr).unwrap_or(&f64::INFINITY) {
                    came_from.insert(nbr.clone(), node.clone());
                    g_score.insert(nbr.clone(), tentative);
                    let f_score = tentative + heuristic(nbr);
                    open.push(State {
                        f: f_score,
                        g: tentative,
                        node: nbr.clone(),
                    });
                }
            }
        }
    }

    Ok(Value::Null)
}

fn graph_zero_one_bfs(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new(
            "graph_zero_one_bfs(graph, start) requires 2 args",
            None,
        ));
    }
    let g = match &args[0] {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Graph(gr) => gr.clone(),
            _ => {
                return Err(RuntimeError::new(
                    "graph_zero_one_bfs: first arg must be Graph",
                    None,
                ))
            }
        },
        _ => {
            return Err(RuntimeError::new(
                "graph_zero_one_bfs: first arg must be Graph",
                None,
            ))
        }
    };
    let start = args[1]
        .as_text()
        .ok_or_else(|| RuntimeError::new("graph_zero_one_bfs: start must be text", None))?;
    let graph = g.borrow();

    let mut dist: HashMap<String, i64> = HashMap::new();
    for node in graph.adj.keys() {
        dist.insert(node.clone(), i64::MAX);
    }
    if !dist.contains_key(&start) {
        dist.insert(start.clone(), i64::MAX);
    }
    dist.insert(start.clone(), 0);

    let mut dq: VecDeque<String> = VecDeque::new();
    dq.push_back(start.clone());

    while let Some(u) = dq.pop_front() {
        let du = *dist.get(&u).unwrap_or(&i64::MAX);
        if du == i64::MAX {
            continue;
        }
        if let Some(nei) = graph.adj.get(&u) {
            for (v, w) in nei {
                let w_int = w.round() as i64;
                if w_int != 0 && w_int != 1 {
                    return Err(RuntimeError::new(
                        "graph_zero_one_bfs: edge weights must be 0 or 1",
                        None,
                    ));
                }
                let cand = du.saturating_add(w_int);
                let dv = dist.entry(v.clone()).or_insert(i64::MAX);
                if cand < *dv {
                    *dv = cand;
                    if w_int == 0 {
                        dq.push_front(v.clone());
                    } else {
                        dq.push_back(v.clone());
                    }
                }
            }
        }
    }

    Ok(Value::make_map(
        dist.into_iter()
            .map(|(k, v)| (k, Value::SmallInt(v)))
            .collect(),
    ))
}

fn graph_bridges(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("graph_bridges(graph)", None));
    }
    let g = match &args[0] {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Graph(gr) => gr.clone(),
            _ => {
                return Err(RuntimeError::new(
                    "graph_bridges: first arg must be Graph",
                    None,
                ))
            }
        },
        _ => {
            return Err(RuntimeError::new(
                "graph_bridges: first arg must be Graph",
                None,
            ))
        }
    };
    let graph = g.borrow();
    if graph.directed {
        return Err(RuntimeError::new(
            "graph_bridges expects undirected graph",
            None,
        ));
    }
    let mut timer = 0i32;
    let mut tin: HashMap<String, i32> = HashMap::new();
    let mut low: HashMap<String, i32> = HashMap::new();
    let mut used: HashSet<String> = HashSet::new();
    let mut bridges: Vec<(String, String)> = Vec::new();

    fn dfs(
        u: &str,
        p: Option<&str>,
        g: &HashMap<String, Vec<(String, f64)>>,
        used: &mut HashSet<String>,
        tin: &mut HashMap<String, i32>,
        low: &mut HashMap<String, i32>,
        timer: &mut i32,
        bridges: &mut Vec<(String, String)>,
    ) {
        used.insert(u.to_string());
        *timer += 1;
        tin.insert(u.to_string(), *timer);
        low.insert(u.to_string(), *timer);
        if let Some(nei) = g.get(u) {
            for (v, _) in nei {
                if Some(v.as_str()) == p {
                    continue;
                }
                if used.contains(v) {
                    let low_u = low.get_mut(u).unwrap();
                    let t_v = tin.get(v).copied().unwrap_or(*low_u);
                    if t_v < *low_u {
                        *low_u = t_v;
                    }
                } else {
                    dfs(v, Some(u), g, used, tin, low, timer, bridges);
                    let low_v = *low.get(v).unwrap();
                    let low_u = low.get_mut(u).unwrap();
                    if low_v < *low_u {
                        *low_u = low_v;
                    }
                    let t_u = *tin.get(u).unwrap();
                    if low_v > t_u {
                        let mut e = (u.to_string(), v.clone());
                        if e.0 > e.1 {
                            std::mem::swap(&mut e.0, &mut e.1);
                        }
                        bridges.push(e);
                    }
                }
            }
        }
    }

    for node in graph.adj.keys() {
        if !used.contains(node) {
            dfs(
                node,
                None,
                &graph.adj,
                &mut used,
                &mut tin,
                &mut low,
                &mut timer,
                &mut bridges,
            );
        }
    }
    bridges.sort();
    let list = bridges
        .into_iter()
        .map(|(u, v)| {
            let mut m = HashMap::new();
            m.insert("u".into(), Value::make_text(u));
            m.insert("v".into(), Value::make_text(v));
            Value::make_map(m)
        })
        .collect();
    Ok(Value::make_list(list))
}

fn graph_articulation_points(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("graph_articulation_points(graph)", None));
    }
    let g = match &args[0] {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Graph(gr) => gr.clone(),
            _ => {
                return Err(RuntimeError::new(
                    "graph_articulation_points: first arg must be Graph",
                    None,
                ))
            }
        },
        _ => {
            return Err(RuntimeError::new(
                "graph_articulation_points: first arg must be Graph",
                None,
            ))
        }
    };
    let graph = g.borrow();
    if graph.directed {
        return Err(RuntimeError::new(
            "graph_articulation_points expects undirected graph",
            None,
        ));
    }
    let mut timer = 0i32;
    let mut tin: HashMap<String, i32> = HashMap::new();
    let mut low: HashMap<String, i32> = HashMap::new();
    let mut used: HashSet<String> = HashSet::new();
    let mut points: HashSet<String> = HashSet::new();

    fn dfs(
        u: &str,
        p: Option<&str>,
        g: &HashMap<String, Vec<(String, f64)>>,
        used: &mut HashSet<String>,
        tin: &mut HashMap<String, i32>,
        low: &mut HashMap<String, i32>,
        timer: &mut i32,
        points: &mut HashSet<String>,
    ) {
        used.insert(u.to_string());
        *timer += 1;
        tin.insert(u.to_string(), *timer);
        low.insert(u.to_string(), *timer);
        let mut child = 0;
        if let Some(nei) = g.get(u) {
            for (v, _) in nei {
                if Some(v.as_str()) == p {
                    continue;
                }
                if used.contains(v) {
                    let low_u = low.get_mut(u).unwrap();
                    let t_v = tin.get(v).copied().unwrap_or(*low_u);
                    if t_v < *low_u {
                        *low_u = t_v;
                    }
                } else {
                    dfs(v, Some(u), g, used, tin, low, timer, points);
                    child += 1;
                    let low_v = *low.get(v).unwrap();
                    let low_u = low.get_mut(u).unwrap();
                    if low_v < *low_u {
                        *low_u = low_v;
                    }
                    let t_u = *tin.get(u).unwrap();
                    if p.is_some() && low_v >= t_u {
                        points.insert(u.to_string());
                    }
                }
            }
        }
        if p.is_none() && child > 1 {
            points.insert(u.to_string());
        }
    }

    for node in graph.adj.keys() {
        if !used.contains(node) {
            dfs(
                node,
                None,
                &graph.adj,
                &mut used,
                &mut tin,
                &mut low,
                &mut timer,
                &mut points,
            );
        }
    }

    let mut list: Vec<String> = points.into_iter().collect();
    list.sort();
    Ok(Value::make_list(
        list.into_iter().map(Value::make_text).collect(),
    ))
}

fn graph_dials(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() < 2 {
        return Err(RuntimeError::new(
            "graph_dials(graph, start, [max_w]) requires at least graph + start",
            None,
        ));
    }
    let g = match &args[0] {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Graph(gr) => gr.clone(),
            _ => {
                return Err(RuntimeError::new(
                    "graph_dials: first arg must be Graph",
                    None,
                ))
            }
        },
        _ => {
            return Err(RuntimeError::new(
                "graph_dials: first arg must be Graph",
                None,
            ))
        }
    };
    let start = args[1]
        .as_text()
        .ok_or_else(|| RuntimeError::new("graph_dials: start must be text", None))?;
    let max_w = args.get(2).and_then(|v| v.as_i64()).unwrap_or(10).max(1) as usize;

    let graph = g.borrow();
    let mut dist: HashMap<String, i64> = HashMap::new();
    for node in graph.adj.keys() {
        dist.insert(node.clone(), i64::MAX);
    }
    if !dist.contains_key(&start) {
        dist.insert(start.clone(), i64::MAX);
    }
    dist.insert(start.clone(), 0);

    let bucket_count = max_w * graph.adj.len().max(1);
    let mut buckets: Vec<Vec<String>> = vec![Vec::new(); bucket_count];
    buckets[0].push(start.clone());
    let mut idx = 0usize;

    while idx < buckets.len() {
        while let Some(u) = buckets[idx].pop() {
            let du = *dist.get(&u).unwrap_or(&i64::MAX);
            if du < idx as i64 {
                continue;
            }
            if let Some(nei) = graph.adj.get(&u) {
                for (v, w) in nei {
                    let w_int = w.round() as i64;
                    if w_int < 0 {
                        return Err(RuntimeError::new(
                            "graph_dials: weights must be non-negative integers",
                            None,
                        ));
                    }
                    let cand = du.saturating_add(w_int);
                    let dv = dist.entry(v.clone()).or_insert(i64::MAX);
                    if cand < *dv {
                        *dv = cand;
                        let b = (cand as usize) % bucket_count;
                        buckets[b].push(v.clone());
                    }
                }
            }
        }
        idx += 1;
    }

    Ok(Value::make_map(
        dist.into_iter()
            .map(|(k, v)| (k, Value::SmallInt(v)))
            .collect(),
    ))
}

// --- SCC (Tarjan) ---
fn graph_scc_tarjan(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("graph_scc(graph)", None));
    }
    let g = match &args[0] {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Graph(gr) => gr.clone(),
            _ => {
                return Err(RuntimeError::new(
                    "graph_scc: first arg must be Graph",
                    None,
                ))
            }
        },
        _ => {
            return Err(RuntimeError::new(
                "graph_scc: first arg must be Graph",
                None,
            ))
        }
    };
    let graph = g.borrow();
    let mut index = 0;
    let mut stack: Vec<String> = Vec::new();
    let mut on_stack: HashSet<String> = HashSet::new();
    let mut indices: HashMap<String, i32> = HashMap::new();
    let mut low: HashMap<String, i32> = HashMap::new();
    let mut comps: Vec<Vec<Value>> = Vec::new();

    for node in graph.adj.keys() {
        if !indices.contains_key(node) {
            strong_connect(
                node.clone(),
                &graph.adj,
                &mut index,
                &mut stack,
                &mut on_stack,
                &mut indices,
                &mut low,
                &mut comps,
            );
        }
    }
    Ok(Value::make_list(
        comps.into_iter().map(Value::make_list).collect(),
    ))
}

fn strong_connect(
    v: String,
    adj: &HashMap<String, Vec<(String, f64)>>,
    index: &mut i32,
    stack: &mut Vec<String>,
    on_stack: &mut HashSet<String>,
    indices: &mut HashMap<String, i32>,
    low: &mut HashMap<String, i32>,
    comps: &mut Vec<Vec<Value>>,
) {
    *index += 1;
    indices.insert(v.clone(), *index);
    low.insert(v.clone(), *index);
    stack.push(v.clone());
    on_stack.insert(v.clone());

    if let Some(neigh) = adj.get(&v) {
        for (w, _) in neigh {
            if !indices.contains_key(w) {
                strong_connect(w.clone(), adj, index, stack, on_stack, indices, low, comps);
                if let (Some(lv), Some(lw)) = (low.get(&v).copied(), low.get(w).copied()) {
                    low.insert(v.clone(), lv.min(lw));
                }
            } else if on_stack.contains(w) {
                if let (Some(lv), Some(iw)) = (low.get(&v).copied(), indices.get(w).copied()) {
                    low.insert(v.clone(), lv.min(iw));
                }
            }
        }
    }

    if let (Some(lv), Some(iv)) = (low.get(&v).copied(), indices.get(&v).copied()) {
        if lv == iv {
            let mut comp = Vec::new();
            while let Some(w) = stack.pop() {
                on_stack.remove(&w);
                comp.push(Value::make_text(w.clone()));
                if w == v {
                    break;
                }
            }
            comps.push(comp);
        }
    }
}

// --- Toposort (Kahn) ---
fn graph_toposort(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("graph_toposort(graph)", None));
    }
    let g = match &args[0] {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Graph(gr) => gr.clone(),
            _ => {
                return Err(RuntimeError::new(
                    "graph_toposort: first arg must be Graph",
                    None,
                ))
            }
        },
        _ => {
            return Err(RuntimeError::new(
                "graph_toposort: first arg must be Graph",
                None,
            ))
        }
    };
    let graph = g.borrow();
    if !graph.directed {
        return Err(RuntimeError::new(
            "graph_toposort requires directed graph",
            None,
        ));
    }
    let mut indeg: HashMap<String, usize> = HashMap::new();
    for (u, neigh) in graph.adj.iter() {
        indeg.entry(u.clone()).or_insert(0);
        for (v, _) in neigh {
            *indeg.entry(v.clone()).or_insert(0) += 1;
        }
    }
    let mut q: VecDeque<String> = indeg
        .iter()
        .filter_map(|(n, &d)| if d == 0 { Some(n.clone()) } else { None })
        .collect();
    let mut order = Vec::new();
    let mut deg = indeg.clone();
    while let Some(u) = q.pop_front() {
        order.push(Value::make_text(u.clone()));
        if let Some(neigh) = graph.adj.get(&u) {
            for (v, _) in neigh {
                if let Some(d) = deg.get_mut(v) {
                    *d -= 1;
                    if *d == 0 {
                        q.push_back(v.clone());
                    }
                }
            }
        }
    }
    if order.len() != indeg.len() {
        return Err(RuntimeError::new("graph_toposort: cycle detected", None));
    }
    Ok(Value::make_list(order))
}

// --- Floyd-Warshall ---
fn graph_floyd_warshall(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("graph_floyd_warshall(graph)", None));
    }
    let g = match &args[0] {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Graph(gr) => gr.clone(),
            _ => {
                return Err(RuntimeError::new(
                    "graph_floyd_warshall: first arg must be Graph",
                    None,
                ))
            }
        },
        _ => {
            return Err(RuntimeError::new(
                "graph_floyd_warshall: first arg must be Graph",
                None,
            ))
        }
    };
    let graph = g.borrow();
    let mut nodes: Vec<String> = graph.adj.keys().cloned().collect();
    // include isolated neighbors
    for neigh in graph.adj.values() {
        for (v, _) in neigh {
            if !nodes.contains(v) {
                nodes.push(v.clone());
            }
        }
    }
    let n = nodes.len();
    let mut dist = vec![vec![f64::INFINITY; n]; n];
    for i in 0..n {
        dist[i][i] = 0.0;
    }
    let idx = |name: &String, nodes: &Vec<String>| nodes.iter().position(|x| x == name).unwrap();

    for (u, neigh) in graph.adj.iter() {
        let iu = idx(u, &nodes);
        for (v, w) in neigh {
            let iv = idx(v, &nodes);
            if *w < dist[iu][iv] {
                dist[iu][iv] = *w;
                if !graph.directed {
                    dist[iv][iu] = *w;
                }
            }
        }
    }
    for k in 0..n {
        for i in 0..n {
            for j in 0..n {
                let alt = dist[i][k] + dist[k][j];
                if alt < dist[i][j] {
                    dist[i][j] = alt;
                }
            }
        }
    }
    // build map: node -> map(dest -> dist)
    let mut outer = HashMap::new();
    for (i, ni) in nodes.iter().enumerate() {
        let mut inner = HashMap::new();
        for (j, nj) in nodes.iter().enumerate() {
            let d = dist[i][j];
            if d.is_finite() {
                inner.insert(nj.clone(), Value::Float(d));
            }
        }
        outer.insert(ni.clone(), Value::make_map(inner));
    }
    Ok(Value::make_map(outer))
}
