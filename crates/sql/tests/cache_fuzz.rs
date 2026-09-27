use std::sync::Arc;

use shahrah_sql::analysis::{analyse, KeyType, Policy};
use shahrah_sql::cache::Cache;

fn policy() -> Policy {
    Policy::new()
        .with_key("users", "id", KeyType::Int)
        .with_key("orders", "user_id", KeyType::Int)
        .with_key("names", "id", KeyType::Text)
        .with_key("things", "ref", KeyType::Uuid)
        .with_broadcast("countries")
}

fn seeded(mut state: u64) -> impl FnMut() -> u64 {
    move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    }
}

fn ints() -> Vec<String> {
    vec![
        "0", "1", "-1", "+1", "7", "-7", "42", "0042", "9223372036854775807",
        "-9223372036854775808", "1e3", "1.0", "0x1f", "1_000",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn texts() -> Vec<String> {
    vec![
        "'ali'", "''", "'it''s'", "'a b'", "'1'", "'-1'", "'کاربر'", "'x\ty'",
        "'--not a comment'", "'/* not a hint */'", "'\"quoted\"'",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn shapes() -> Vec<&'static str> {
    vec![
        "select name from users where id = {}",
        "select * from users where id={} ",
        "SELECT * FROM users WHERE id = {}",
        "select * from users where {} = id",
        "update users set name = 'n' where id = {}",
        "delete from users where id = {}",
        "insert into users (id, name) values ({}, 'n')",
        "select * from users where id = {} and name = 'k'",
        "select * from users where name = 'k' and id = {}",
        "select * from users where id = {} limit 4",
        "select * from users where id = {} order by name desc",
        "select count(*) from users where id = {}",
        "/* shahrah: shard=2 */ select * from users where id = {}",
        "/* shahrah: key=99 */ select * from users where id = {}",
        "select * from users where id = {} -- trailing\n",
        "select * from users /* middle */ where id = {}",
        "select * from orders where user_id = {}",
        "select * from countries where id = {}",
        "select * from users where id in ({})",
        "select * from users where id = {}::bigint",
        "select * from users where id = ({})",
        "select * from users where id = {} for update",
        "with recent as (select {} as k) select * from users where id = 1",
    ]
}

fn text_shapes() -> Vec<&'static str> {
    vec![
        "select * from names where id = {}",
        "update names set id = 'z' where id = {}",
        "select * from names where id = {} limit 2",
        "insert into names (id) values ({})",
        "select * from names where id = {} and id <> 'q'",
    ]
}

fn every_statement() -> Vec<String> {
    let mut out = Vec::new();
    for shape in shapes() {
        for value in ints() {
            out.push(shape.replace("{}", &value));
        }
    }
    for shape in text_shapes() {
        for value in texts() {
            out.push(shape.replace("{}", &value));
        }
    }
    for nasty in [
        "select * from users where id = 1; select 1",
        "select * from users where id = 1 /* unterminated",
        "select * from users where id = 1 /* shahrah: key=2 */ /* shahrah: key=3 */",
        "select * from users where id = B'1010'",
        "select * from users where id = X'ff'",
        "select * from users where id = 1::text::int",
        "select * from names where id = $$dollar$$",
        "select * from names where id = e'esc\\'aped'",
        "select * from names where id = U&'d\\0061t'",
        "select * from users where id = 1 union select * from users where id = 2",
        "select * from users where id = (select 1)",
        "select * from users where id = case when true then 1 else 2 end",
        "select * from users where id = 1 and id = 2",
        "select * from things where ref = '0b6a6e2c-6a13-4f6f-9a6e-2c6a134f6f9a'",
        "select * from things where ref = 'not-a-uuid'",
        "SeLeCt * FrOm UsErS wHeRe Id = 1",
        "select\n\t*\nfrom users\nwhere id\n=\n1",
        "select * from users where id = 1                     ",
        "select * from users where id = -0",
        "select * from users where id = - 1",
        "select * from users where id = --1\n1",
    ] {
        out.push((*nasty).to_owned());
    }
    out.push("select * from users where id = $1".to_owned());
    out.push("select * from users where id = $1 and name = 'k'".to_owned());
    out.push("select 1".to_owned());
    out.push("begin".to_owned());
    out.push("commit".to_owned());
    out.push("select * from users".to_owned());
    out
}

fn agrees(cache: &Cache, sql: &str, policy: &Policy, when: &str) {
    let fresh = analyse(sql, policy);
    let cached = cache.analyse(sql, policy);
    match (fresh, cached) {
        (Ok(fresh), Ok(cached)) => assert_eq!(
            fresh, *cached,
            "{when}: the cache disagreed with a fresh parse for {sql:?}"
        ),
        (Err(fresh), Err(cached)) => assert_eq!(
            fresh.to_string(),
            cached.to_string(),
            "{when}: different refusals for {sql:?}"
        ),
        (fresh, cached) => {
            panic!("{when}: {sql:?}\n  fresh {fresh:?}\n  cached {cached:?}")
        }
    }
}

#[test]
fn every_statement_in_every_order_agrees_with_a_fresh_parse() {
    let policy = policy();
    let statements = every_statement();
    let cache = Cache::new(4096);
    for round in 0..3 {
        for sql in &statements {
            agrees(&cache, sql, &policy, &format!("round {round}"));
        }
    }
    let mut next = seeded(0x9E3779B97F4A7C15);
    for round in 0..6 {
        let mut shuffled = statements.clone();
        for at in (1..shuffled.len()).rev() {
            let with = (next() as usize) % (at + 1);
            shuffled.swap(at, with);
        }
        for sql in &shuffled {
            agrees(&cache, sql, &policy, &format!("shuffle {round}"));
        }
    }
    let counts = cache.counts();
    assert!(counts.hits > 1000, "the cache barely served anything");
    let hot = Cache::new(4096);
    for value in 0..400 {
        let _seen = hot.analyse(&format!("select name from users where id = {value}"), &policy);
    }
    assert!(
        hot.counts().hits >= 398,
        "the shape a real workload repeats stopped being cached: {} hits, {} misses",
        hot.counts().hits,
        hot.counts().misses
    );
}

#[test]
fn a_cache_too_small_to_hold_the_corpus_still_agrees() {
    let policy = policy();
    let statements = every_statement();
    for capacity in [1, 2, 7, 64] {
        let cache = Cache::new(capacity);
        for round in 0..3 {
            for sql in &statements {
                agrees(&cache, sql, &policy, &format!("capacity {capacity} round {round}"));
            }
        }
    }
}

#[test]
fn many_threads_sharing_one_cache_agree_with_a_fresh_parse() {
    let policy = Arc::new(policy());
    let cache = Cache::new(256);
    let statements = Arc::new(every_statement());
    let mut threads = Vec::new();
    for number in 0..8 {
        let cache = Arc::clone(&cache);
        let policy = Arc::clone(&policy);
        let statements = Arc::clone(&statements);
        threads.push(std::thread::spawn(move || {
            for round in 0..4 {
                let start = (number * 13 + round) % statements.len();
                for offset in 0..statements.len() {
                    let at = (start + offset) % statements.len();
                    if let Some(sql) = statements.get(at) {
                        agrees(&cache, sql, &policy, &format!("thread {number}"));
                    }
                }
            }
        }));
    }
    for thread in threads {
        assert!(thread.join().is_ok(), "a thread disagreed with a fresh parse");
    }
}

#[test]
#[ignore]
fn ten_thousand_generated_statements_agree_with_a_fresh_parse() {
    let policy = policy();
    let cache = Cache::new(512);
    let mut next = seeded(0xDEADBEEFCAFEF00D);
    let tables = ["users", "orders", "names", "things", "countries", "absent"];
    let columns = ["id", "user_id", "ref", "name", "other"];
    let operators = ["=", "<>", ">", "in"];
    let mut checked = 0u32;
    for _ in 0..10_000 {
        let pick = |choices: &[&'static str], at: u64| -> &'static str {
            choices
                .get((at as usize) % choices.len().max(1))
                .copied()
                .unwrap_or("users")
        };
        let table = pick(&tables, next());
        let column = pick(&columns, next());
        let operator = pick(&operators, next());
        let value = match (next() as usize) % 9 {
            0 => "0".to_owned(),
            1 => format!("{}", (next() % 1_000_000) as i64),
            2 => format!("-{}", (next() % 1_000_000) as i64),
            3 => format!("{}", i64::MAX),
            4 => "1.5".to_owned(),
            5 => format!("'{}'", (next() % 999)),
            6 => "'it''s'".to_owned(),
            7 => "$1".to_owned(),
            _ => "null".to_owned(),
        };
        let value = if operator == "in" { format!("({value})") } else { value };
        let hint = match (next() as usize) % 6 {
            0 => "/* shahrah: shard=3 */ ",
            1 => "/* shahrah: key=88 */ ",
            2 => "/* plain */ ",
            _ => "",
        };
        let tail = match (next() as usize) % 5 {
            0 => " limit 5",
            1 => " order by name",
            2 => " for update",
            _ => "",
        };
        let sql = match (next() as usize) % 4 {
            0 => format!("{hint}select * from {table} where {column} {operator} {value}{tail}"),
            1 => format!("{hint}update {table} set name = 'x' where {column} {operator} {value}"),
            2 => format!("{hint}delete from {table} where {column} {operator} {value}"),
            _ => format!("{hint}select count(*) from {table} where {column} {operator} {value}"),
        };
        agrees(&cache, &sql, &policy, "generated");
        checked = checked.saturating_add(1);
    }
    assert_eq!(checked, 10_000);
}
