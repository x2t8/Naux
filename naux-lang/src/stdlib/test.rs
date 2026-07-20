use crate::runtime::env::Env;
use crate::runtime::error::RuntimeError;
use crate::runtime::value::Value;

pub fn register_tests(env: &mut Env) {
    env.set_builtin("assert_equal", builtin_assert_equal);
}

fn builtin_assert_equal(args: Vec<Value>) -> Result<Value, RuntimeError> {
    if args.len() != 3 {
        return Err(RuntimeError::new("assert_equal(a, b, msg)", None));
    }
    let expected = &args[0];
    let actual = &args[1];
    if expected == actual {
        Ok(Value::Bool(true))
    } else {
        Ok(Value::Bool(false))
    }
}
