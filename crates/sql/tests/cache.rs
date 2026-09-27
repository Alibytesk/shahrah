use shahrah_sql::analysis::{analyse, KeyType, Policy};
use shahrah_sql::cache::Cache;

fn answered(cache: &Cache, sql: &str, policy: &Policy) -> shahrah_sql::analysis::Analysis {
    match cache.analyse(sql, policy) {
        Ok(found) => shahrah_sql::analysis::Analysis::clone(&found),
        Err(cause) => panic!("{sql}\n  did not analyse: {cause}"),
    }
}

fn fresh(sql: &str, policy: &Policy) -> shahrah_sql::analysis::Analysis {
    match analyse(sql, policy) {
        Ok(found) => found,
        Err(cause) => panic!("{sql}\n  did not analyse: {cause}"),
    }
}

fn policy() -> Policy {
    Policy::new()
        .with_key("users", "id", KeyType::Int)
        .with_key("orders", "user_id", KeyType::Int)
        .with_key("names", "id", KeyType::Text)
        .with_broadcast("countries")
}

fn corpus() -> Vec<String> {
    let mut out = Vec::new();
    for value in [1_i64, 2, 7, -1, 0, 4242, i64::MAX, i64::MIN] {
        out.push(format!("select name from users where id = {value}"));
        out.push(format!("select * from users where id={value} and name = 'x'"));
        out.push(format!("update users set name = 'a' where id = {value}"));
        out.push(format!("delete from users where id = {value}"));
        out.push(format!("insert into users (id, name) values ({value}, 'n')"));
        out.push(format!("select * from orders where user_id = {value} limit 3"));
        out.push(format!("select * from orders where user_id = {value} limit 9"));
        out.push(format!("/* shahrah: shard=2 */ select * from users where id = {value}"));
        out.push(format!("select count(*) from users where id = {value}"));
    }
    for value in ["ali", "b", "it''s", "", "x y", "1"] {
        out.push(format!("select * from names where id = '{value}'"));
        out.push(format!("update names set id = 'z' where id = '{value}'"));
    }
    out.push("select * from countries".to_owned());
    out.push("select * from users where id = $1".to_owned());
    out.push("select * from users where id = $1 and name = 'k'".to_owned());
    out.push("select * from users".to_owned());
    out.push("select 1".to_owned());
    out.push("begin".to_owned());
    out.push("select * from users where id = 5 order by name desc limit 2".to_owned());
    out
}

#[test]
fn the_cache_answers_exactly_what_a_fresh_parse_would() {
    let cache = Cache::new(4096);
    let policy = policy();
    let statements = corpus();
    for pass in 0..4 {
        for sql in &statements {
            let fresh = analyse(sql, &policy);
            let cached = cache.analyse(sql, &policy);
            match (fresh, cached) {
                (Ok(fresh), Ok(cached)) => assert_eq!(
                    fresh,
                    *cached,
                    "pass {pass}: the cache disagreed with a fresh parse for {sql}"
                ),
                (Err(fresh), Err(cached)) => {
                    assert_eq!(fresh.to_string(), cached.to_string(), "pass {pass}: {sql}");
                }
                (fresh, cached) => panic!(
                    "pass {pass}: {sql}\n  fresh {fresh:?}\n  cached {cached:?}"
                ),
            }
        }
    }
    assert!(cache.counts().hits > 0, "nothing was ever served from the cache");
}

#[test]
fn statements_of_one_shape_do_not_borrow_each_others_keys() {
    let cache = Cache::new(4096);
    let policy = policy();
    let first = "select * from users where id = 11 and name = 'a'";
    let second = "select * from users where id = 22 and name = 'a'";
    let _warm = cache.analyse(first, &policy);
    assert_eq!(answered(&cache, second, &policy), fresh(second, &policy));
}

#[test]
fn a_limit_is_never_taken_from_another_statement() {
    let cache = Cache::new(4096);
    let policy = policy();
    let _warm = cache.analyse("select * from users where id = 1 limit 5", &policy);
    let seen = answered(&cache, "select * from users where id = 1 limit 900", &policy);
    assert_eq!(seen.limit, Some(900));
}

#[test]
fn a_hint_on_one_statement_does_not_leak_to_another() {
    let cache = Cache::new(4096);
    let policy = policy();
    let hinted = "/* shahrah: shard=4 */ select * from users where id = 3";
    let plain = "select * from users where id = 3";
    let _warm = cache.analyse(hinted, &policy);
    assert_eq!(answered(&cache, plain, &policy), fresh(plain, &policy));
}

#[test]
fn the_cache_serves_a_repeated_shape_without_reparsing() {
    let cache = Cache::new(4096);
    let policy = policy();
    for value in 0..500 {
        let _answered = cache.analyse(
            &format!("select name from users where id = {value}"),
            &policy,
        );
    }
    let counts = cache.counts();
    assert!(
        counts.hits >= 498,
        "500 statements of one shape produced {} hits and {} misses",
        counts.hits,
        counts.misses
    );
    assert_eq!(counts.entries, 1, "one shape should hold one entry");
}

#[test]
fn a_shape_the_cache_cannot_hold_is_still_answered_correctly_every_time() {
    let policy = policy();
    let cache = Cache::new(64);
    let statements: Vec<String> = [1_i64, 2, 7, -1, 0, 4242]
        .iter()
        .map(|key| format!("select name from users where id = {key} order by name limit 20"))
        .collect();
    for round in 0..4 {
        for sql in &statements {
            assert_eq!(
                answered(&cache, sql, &policy),
                fresh(sql, &policy),
                "round {round} of {sql} did not agree with a fresh parse"
            );
        }
    }
}

#[test]
fn a_shape_the_cache_cannot_hold_does_not_crowd_out_one_it_can() {
    let policy = policy();
    let cache = Cache::new(4);
    for key in 0..64_i64 {
        let sql = format!("select name from users where id = {key} limit {key}");
        let _seen = answered(&cache, &sql, &policy);
    }
    let keeper = "select name from users where id = 5";
    let _warm = answered(&cache, keeper, &policy);
    let before = cache.counts().hits;
    let _again = answered(&cache, keeper, &policy);
    assert!(
        cache.counts().hits > before,
        "sixty-four shapes that cannot be held should not have evicted the one that can"
    );
}

#[test]
fn a_key_beside_another_literal_is_now_held_by_shape() {
    let policy = policy();
    let cache = Cache::new(64);
    let warm = "select name from users where id = 1 and name = 'ali'";
    let _first = answered(&cache, warm, &policy);
    let before = cache.counts().hits;
    for key in 2..12_i64 {
        let sql = format!("select name from users where id = {key} and name = 'ali'");
        assert_eq!(
            answered(&cache, &sql, &policy),
            fresh(&sql, &policy),
            "{sql} did not agree with a fresh parse"
        );
    }
    assert!(
        cache.counts().hits >= before.saturating_add(10),
        "a statement whose key sits beside another literal should be served from \
         the shape, not reparsed: hits went from {before} to {}",
        cache.counts().hits
    );
}

#[test]
fn the_second_literal_cannot_stand_in_for_the_key() {
    let policy = policy();
    let cache = Cache::new(64);
    let corpus = [
        "select name from users where id = 1 and name = 'a'",
        "select name from users where id = 2 and name = 'b'",
        "select name from users where name = 'a' and id = 3",
    ];
    for sql in corpus {
        let _warm = answered(&cache, sql, &policy);
    }
    for sql in corpus {
        assert_eq!(
            answered(&cache, sql, &policy),
            fresh(sql, &policy),
            "{sql} took its key from the wrong constant"
        );
    }
}
