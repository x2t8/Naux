use std::cell::RefCell;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::cmp::Ordering;
use std::rc::Rc;

use crate::runtime::env::Env;
use crate::runtime::error::RuntimeError;
use crate::runtime::value::{Graph, Value};

pub fn register_graph(env: &mut Env) {
    env.set_builtin("graph_new", graph_new);
    env.set_builtin("graph_add_edge", graph_add_edge);
    env.set_builtin("graph_neighbors", graph_neighbors);
    env.set_builtin("graph_bfs", graph_bfs);
    env.set_builtin("graph_dijkstra", graph_dijkstra);
}

fn graph_new(args: Vec<Value>) -> Result<Value, RuntimeError> {
    let directed = match args.get(0) {
        Some(Value::Bool(b)) => *b,
        _ => false,
    };
    let g = Graph {
        directed,
        adj: HashMap::new(),
    };
    Ok(Value::Graph(Rc::new(RefCell::new(g))))
}

fn graph_add_edge(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() < 3 {
        return Err(RuntimeError::new("graph_add_edge requires at least 3 args: (graph, from, to, [weight])", None));
    }
    let g = match &args[0] {
        Value::Graph(rc) => rc.clone(),
        _ => return Err(RuntimeError::new("graph_add_edge: first argument must be a Graph", None)),
    };
    let from = match &args[1] {
        Value::Text(s) => s.clone(),
        _ => return Err(RuntimeError::new("graph_add_edge: from must be text", None)),
    };
    let to = match &args[2] {
        Value::Text(s) => s.clone(),
        _ => return Err(RuntimeError::new("graph_add_edge: to must be text", None)),
    };
    let weight = match args.get(3) {
        Some(Value::Number(n)) => *n,
        Some(_) => return Err(RuntimeError::new("graph_add_edge: weight must be number", None)),
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
        Value::Graph(rc) => rc.clone(),
        _ => return Err(RuntimeError::new("graph_neighbors: first arg must be Graph", None)),
    };
    let node = match &args[1] {
        Value::Text(s) => s.clone(),
        _ => return Err(RuntimeError::new("graph_neighbors: node must be text", None)),
    };
    let graph = g.borrow();
    let neigh = graph
        .adj
        .get(&node)
        .map(|v| v.iter().map(|(n, _)| Value::Text(n.clone())).collect::<Vec<_>>())
        .unwrap_or_else(Vec::new);
    Ok(Value::List(neigh))
}

fn graph_bfs(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::new("graph_bfs(graph, start) requires 2 args", None));
    }
    let g = match &args[0] {
        Value::Graph(rc) => rc.clone(),
        _ => return Err(RuntimeError::new("graph_bfs: first arg must be Graph", None)),
    };
    let start = match &args[1] {
        Value::Text(s) => s.clone(),
        _ => return Err(RuntimeError::new("graph_bfs: start must be text", None)),
    };

    let graph = g.borrow();
    let mut visited = HashSet::new();
    let mut order = Vec::new();
    let mut q = VecDeque::new();

    visited.insert(start.clone());
    q.push_back(start.clone());

    while let Some(node) = q.pop_front() {
        order.push(Value::Text(node.clone()));
        if let Some(neigh) = graph.adj.get(&node) {
            for (nbr, _) in neigh {
                if visited.insert(nbr.clone()) {
                    q.push_back(nbr.clone());
                }
            }
        }
    }

    Ok(Value::List(order))
}

fn graph_dijkstra(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() < 3 {
        return Err(RuntimeError::new("graph_dijkstra(graph, source, target)", None));
    }
    let g = match &args[0] {
        Value::Graph(rc) => rc.clone(),
        _ => return Err(RuntimeError::new("graph_dijkstra: first arg must be Graph", None)),
    };
    let source = match &args[1] {
        Value::Text(s) => s.clone(),
        _ => return Err(RuntimeError::new("graph_dijkstra: source must be text", None)),
    };
    let target = match &args[2] {
        Value::Text(s) => s.clone(),
        _ => return Err(RuntimeError::new("graph_dijkstra: target must be text", None)),
    };

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
    path_nodes.push(Value::Text(cur.clone()));
    while let Some(p) = prev.get(&cur) {
        cur = p.clone();
        path_nodes.push(Value::Text(cur.clone()));
        if cur == source {
            break;
        }
    }
    path_nodes.reverse();
    Ok(Value::List(path_nodes))
}
