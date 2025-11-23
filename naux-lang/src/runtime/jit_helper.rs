use crate::runtime::value::{RawValue, RawValuePayload, Value, ValueTag};
use crate::runtime::value::{NauxObj};
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;

unsafe fn raw_to_value(raw: *const RawValue) -> Option<Value> {
    if raw.is_null() {
        return None;
    }
    Some(Value::from_raw(&*raw))
}

unsafe fn write_raw(out: *mut RawValue, value: Value) {
    if out.is_null() {
        return;
    }
    *out = value.to_raw();
}

fn len_of_value(value: &Value) -> usize {
    match value {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Text(s) => s.chars().count(),
            NauxObj::List(v) => v.borrow().len(),
            NauxObj::Map(m) => m.borrow().len(),
            _ => 0,
        },
        _ => 0,
    }
}

#[no_mangle]
pub extern "C" fn jit_helper_len(arg: *const RawValue, out: *mut RawValue) -> i32 {
    unsafe {
        if let Some(value) = raw_to_value(arg) {
            let len = len_of_value(&value);
            write_raw(out, Value::SmallInt(len as i64));
            0
        } else {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn jit_helper_index(target: *const RawValue, idx: *const RawValue, out: *mut RawValue) -> i32 {
    unsafe {
        let target_value = match raw_to_value(target) {
            Some(v) => v,
            None => return -1,
        };
        let idx_value = match raw_to_value(idx) {
            Some(v) => v,
            None => return -1,
        };
        let result = match (&target_value, idx_value) {
            (Value::RcObj(rc), Value::SmallInt(n)) => match rc.as_ref() {
                NauxObj::List(list) => list.borrow().get(n as usize).cloned().unwrap_or(Value::Null),
                _ => Value::Null,
            },
            (Value::RcObj(rc), Value::Float(n)) => match rc.as_ref() {
                NauxObj::List(list) => list.borrow().get(n as usize).cloned().unwrap_or(Value::Null),
                _ => Value::Null,
            },
            (Value::RcObj(rc), Value::RcObj(krc)) => match (rc.as_ref(), krc.as_ref()) {
                (NauxObj::Map(map), NauxObj::Text(key)) => map.borrow().get(key).cloned().unwrap_or(Value::Null),
                _ => Value::Null,
            },
            _ => Value::Null,
        };
        write_raw(out, result);
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn len_helper_tests() {
        let v = Value::make_text("abc");
        let raw = v.to_raw();
        let mut out = RawValue::null();
        unsafe {
            assert_eq!(jit_helper_len(&raw, &mut out), 0);
            let res = RawValue::from_raw(&out);
            assert!(matches!(res, Value::SmallInt(3)));
        }
    }

    #[test]
    fn index_helper_tests() {
        let list = Value::make_list(vec![Value::SmallInt(1), Value::SmallInt(2)]);
        let raw_list = list.to_raw();
        let idx = Value::SmallInt(1).to_raw();
        let mut out = RawValue::null();
        unsafe {
            assert_eq!(jit_helper_index(&raw_list, &idx, &mut out), 0);
            let res = RawValue::from_raw(&out);
            assert!(matches!(res, Value::SmallInt(2)));
        }
    }
}
