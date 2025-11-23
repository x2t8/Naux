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
    env.set_builtin("graph_scc", graph_scc_tarjan);
    env.set_builtin("graph_toposort", graph_toposort);
    env.set_builtin("graph_floyd_warshall", graph_floyd_warshall);
}

fn graph_new(args: Vec<Value>) -> Result<Value, RuntimeError> {
    let directed = matches!(args.get(0), Some(Value::Bool(true)));
    let g = Graph { directed, adj: HashMap::new() };
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
            _ => return Err(RuntimeError::new("graph_add_edge: first argument must be a Graph", None)),
        },
        _ => return Err(RuntimeError::new("graph_add_edge: first argument must be a Graph", None)),
    };
    let from = args[1].as_text().ok_or_else(|| RuntimeError::new("graph_add_edge: from must be text", None))?;
    let to = args[2].as_text().ok_or_else(|| RuntimeError::new("graph_add_edge: to must be text", None))?;
    let weight = match args.get(3).and_then(|v| v.as_f64()) {
        Some(n) => n,
        None => 1.0,
    };

    {
        let mut graph = g.borrow_mut();
        graph.adj.entry(from.clone()).or_insert_with(Vec::new).push((to.clone(), weight));
        if !graph.directed {
            graph.adj.entry(to).or_insert_with(Vec::new).push((from, weight));
        }
    }
    Ok(Value::Null)
}

fn graph_neighbors(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("graph_neighbors(graph, node) requires 2 args", None));
    }
    let g = match &args[0] {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Graph(g) => g,
            _ => return Err(RuntimeError::new("graph_neighbors: first arg must be Graph", None)),
        },
        _ => return Err(RuntimeError::new("graph_neighbors: first arg must be Graph", None)),
    };
    let node = args[1].as_text().ok_or_else(|| RuntimeError::new("graph_neighbors: node must be text", None))?;
    let graph = g.borrow();
    let neigh = graph
        .adj
        .get(&node)
        .map(|v| v.iter().map(|(n, _)| Value::make_text(n.clone())).collect::<Vec<_>>())
        .unwrap_or_else(Vec::new);
    Ok(Value::make_list(neigh))
}

fn graph_bfs(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("graph_bfs(graph, start) requires 2 args", None));
    }
    let g = match &args[0] {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Graph(g) => g,
            _ => return Err(RuntimeError::new("graph_bfs: first arg must be Graph", None)),
        },
        _ => return Err(RuntimeError::new("graph_bfs: first arg must be Graph", None)),
    };
    let start = args[1].as_text().ok_or_else(|| RuntimeError::new("graph_bfs: start must be text", None))?;

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
        return Err(RuntimeError::new("graph_dijkstra(graph, source, target)", None));
    }
    let g = match &args[0] {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Graph(g) => g,
            _ => return Err(RuntimeError::new("graph_dijkstra: first arg must be Graph", None)),
        },
        _ => return Err(RuntimeError::new("graph_dijkstra: first arg must be Graph", None)),
    };
    let source = args[1].as_text().ok_or_else(|| RuntimeError::new("graph_dijkstra: source must be text", None))?;
    let target = args[2].as_text().ok_or_else(|| RuntimeError::new("graph_dijkstra: target must be text", None))?;

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
            other.cost.partial_cmp(&self.cost).unwrap_or(Ordering::Equal)
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

// --- SCC (Tarjan) ---
fn graph_scc_tarjan(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::new("graph_scc(graph)", None));
    }
    let g = match &args[0] {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Graph(gr) => gr.clone(),
            _ => return Err(RuntimeError::new("graph_scc: first arg must be Graph", None)),
        },
        _ => return Err(RuntimeError::new("graph_scc: first arg must be Graph", None)),
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
    Ok(Value::make_list(comps.into_iter().map(Value::make_list).collect()))
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
                strong_connect(
                    w.clone(),
                    adj,
                    index,
                    stack,
                    on_stack,
                    indices,
                    low,
                    comps,
                );
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
                if w == v { break; }
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
            _ => return Err(RuntimeError::new("graph_toposort: first arg must be Graph", None)),
        },
        _ => return Err(RuntimeError::new("graph_toposort: first arg must be Graph", None)),
    };
    let graph = g.borrow();
    if !graph.directed {
        return Err(RuntimeError::new("graph_toposort requires directed graph", None));
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
            _ => return Err(RuntimeError::new("graph_floyd_warshall: first arg must be Graph", None)),
        },
        _ => return Err(RuntimeError::new("graph_floyd_warshall: first arg must be Graph", None)),
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
    for i in 0..n { dist[i][i] = 0.0; }
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
