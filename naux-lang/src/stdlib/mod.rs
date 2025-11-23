pub mod list;
pub mod map;
pub mod math;
pub mod string;
pub mod graph;
pub mod collections;
pub mod algo;
pub mod test;

use crate::runtime::env::Env;

pub fn register_all(env: &mut Env) {
    graph::register_graph(env);
    collections::register_collections(env);
    math::register_math(env);
    algo::register_algo(env);
    test::register_tests(env);
    // list::register_list(env);
    // string::register_string(env);
}
