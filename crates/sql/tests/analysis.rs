use shahrah_sql::analysis::{
    analyse, canonical, one_statement, Access, Analysis, KeyError, KeySource, KeyType, OwnedKey,
    Policy, PolicyError, Routing, SqlError, TableClass, FORMAT_BINARY, FORMAT_TEXT,
};

fn policy() -> Policy {
    Policy::new()
        .with_key("users", "id", KeyType::Int)
        .with_key("orders", "user_id", KeyType::Int)
        .with_key("names", "id", KeyType::Text)
        .with_broadcast("countries")
}

fn routing(sql: &str) -> Routing {
    match analyse(sql, &policy()) {
        Ok(analysis) => analysis.routing,
        Err(error) => panic!("{sql}\n  did not analyse: {error}"),
    }
}

fn access(sql: &str) -> Access {
    match analyse(sql, &policy()) {
        Ok(analysis) => analysis.access,
        Err(error) => panic!("{sql}\n  did not analyse: {error}"),
    }
}

#[test]
fn a_select_with_a_literal_key_routes() {
    assert_eq!(
        routing("select * from users where id = 42"),
        Routing::Single {
            source: KeySource::Int(42),
            key_type: KeyType::Int,
        }
    );
    assert_eq!(
        routing("SELECT name FROM users WHERE ID = 7 AND region = 'eu'"),
        Routing::Single {
            source: KeySource::Int(7),
            key_type: KeyType::Int,
        }
    );
    assert_eq!(
        routing("select * from users where 42 = id"),
        Routing::Single {
            source: KeySource::Int(42),
            key_type: KeyType::Int,
        }
    );
}

#[test]
fn a_select_with_a_parameter_key_routes_to_the_parameter() {
    assert_eq!(
        routing("select * from users where id = $1"),
        Routing::Single {
            source: KeySource::Parameter(1),
            key_type: KeyType::Int,
        }
    );
    assert_eq!(
        routing("select * from users where region = $1 and id = $2"),
        Routing::Single {
            source: KeySource::Parameter(2),
            key_type: KeyType::Int,
        }
    );
    assert_eq!(
        routing("select * from users where id = $1::bigint"),
        Routing::Single {
            source: KeySource::Parameter(1),
            key_type: KeyType::Int,
        }
    );
}

#[test]
fn a_text_key_is_carried_through() {
    let p = Policy::new().with_key("sessions", "token", KeyType::Text);
    match analyse("select * from sessions where token = 'abc'", &p) {
        Ok(analysis) => assert_eq!(
            analysis.routing,
            Routing::Single {
                source: KeySource::Text("abc".to_owned()),
                key_type: KeyType::Text,
            }
        ),
        Err(error) => panic!("{error}"),
    }
}

#[test]
fn a_key_behind_or_is_not_treated_as_routable() {
    assert_eq!(
        routing("select * from users where id = 1 or id = 2"),
        Routing::KeyMissing {
            table: "users".to_owned()
        }
    );
}

#[test]
fn a_key_compared_with_anything_but_equals_is_not_a_key() {
    for sql in [
        "select * from users where id > 5",
        "select * from users where id in (1, 2)",
        "select * from users where id between 1 and 5",
    ] {
        assert_eq!(
            routing(sql),
            Routing::KeyMissing {
                table: "users".to_owned()
            },
            "{sql}"
        );
    }
}

#[test]
fn a_keyless_select_on_a_sharded_table_is_reported_not_guessed() {
    assert_eq!(
        routing("select count(*) from users"),
        Routing::KeyMissing {
            table: "users".to_owned()
        }
    );
}

#[test]
fn an_unsharded_table_needs_no_key() {
    assert_eq!(routing("select * from countries"), Routing::NoShardedTable);
    assert_eq!(routing("select 1"), Routing::NoShardedTable);
    assert_eq!(routing("select now()"), Routing::NoShardedTable);
}

#[test]
fn inserts_take_the_key_from_the_column_list() {
    assert_eq!(
        routing("insert into users (id, name) values (99, 'ali')"),
        Routing::Single {
            source: KeySource::Int(99),
            key_type: KeyType::Int,
        }
    );
    assert_eq!(
        routing("insert into users (name, id) values ('ali', 99)"),
        Routing::Single {
            source: KeySource::Int(99),
            key_type: KeyType::Int,
        }
    );
    assert_eq!(
        routing("insert into users (name, id) values ($1, $2)"),
        Routing::Single {
            source: KeySource::Parameter(2),
            key_type: KeyType::Int,
        }
    );
    assert_eq!(
        routing("insert into users (name) values ('ali')"),
        Routing::KeyMissing {
            table: "users".to_owned()
        }
    );
}

#[test]
fn updates_and_deletes_route_on_their_where_clause() {
    assert_eq!(
        routing("update users set name = 'x' where id = 5"),
        Routing::Single {
            source: KeySource::Int(5),
            key_type: KeyType::Int,
        }
    );
    assert_eq!(
        routing("delete from users where id = $1"),
        Routing::Single {
            source: KeySource::Parameter(1),
            key_type: KeyType::Int,
        }
    );
    assert_eq!(
        routing("update users set name = 'x'"),
        Routing::KeyMissing {
            table: "users".to_owned()
        }
    );
}

#[test]
fn two_sharded_tables_in_one_statement_are_refused() {
    match routing("select * from users join orders on users.id = orders.user_id where users.id = 1")
    {
        Routing::Unsupported(_) => {}
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn reads_and_writes_are_told_apart() {
    assert_eq!(access("select * from users where id = 1"), Access::Read);
    assert_eq!(access("insert into users (id) values (1)"), Access::Write);
    assert_eq!(access("update users set name='x' where id=1"), Access::Write);
    assert_eq!(access("delete from users where id=1"), Access::Write);
    assert_eq!(access("begin"), Access::TransactionBegin);
    assert_eq!(access("start transaction"), Access::TransactionBegin);
    assert_eq!(access("commit"), Access::TransactionEnd);
    assert_eq!(access("end"), Access::TransactionEnd);
    assert_eq!(access("rollback"), Access::TransactionEnd);
    assert_eq!(access("savepoint a"), Access::TransactionOther);
    assert_eq!(access("set application_name = 'x'"), Access::Utility);
    assert_eq!(access("show all"), Access::Utility);
}

#[test]
fn broken_sql_is_an_error_not_a_guess() {
    match analyse("selct 1", &policy()) {
        Err(SqlError::Parse(_)) => {}
        other => panic!("expected a parse error, got {other:?}"),
    }
}

#[test]
fn a_multi_statement_request_is_refused() {
    match analyse("select 1; select 2", &policy()) {
        Err(SqlError::Multiple { count: 2 }) => {}
        other => panic!("expected Multiple, got {other:?}"),
    }
}

#[test]
fn quoted_and_odd_identifiers_still_resolve() {
    assert_eq!(
        routing(r#"select * from "users" where "id" = 3"#),
        Routing::Single {
            source: KeySource::Int(3),
            key_type: KeyType::Int,
        }
    );
    assert_eq!(
        routing("select * from users u where u.id = 3"),
        Routing::Single {
            source: KeySource::Int(3),
            key_type: KeyType::Int,
        }
    );
}

#[test]
fn comments_and_whitespace_do_not_confuse_it() {
    assert_eq!(
        routing("/* app: checkout */ select * from users\n  where id = 8 -- trailing\n"),
        Routing::Single {
            source: KeySource::Int(8),
            key_type: KeyType::Int,
        }
    );
}

#[test]
fn a_binary_integer_is_widened_the_way_hash_md_says() {
    assert_eq!(
        canonical(Some(&42i16.to_be_bytes()), FORMAT_BINARY, KeyType::Int),
        Ok(OwnedKey::Int(42))
    );
    assert_eq!(
        canonical(Some(&42i32.to_be_bytes()), FORMAT_BINARY, KeyType::Int),
        Ok(OwnedKey::Int(42))
    );
    assert_eq!(
        canonical(Some(&42i64.to_be_bytes()), FORMAT_BINARY, KeyType::Int),
        Ok(OwnedKey::Int(42))
    );
    assert_eq!(
        canonical(Some(&(-1i16).to_be_bytes()), FORMAT_BINARY, KeyType::Int),
        Ok(OwnedKey::Int(-1)),
        "a negative int2 must sign-extend, not zero-extend"
    );
}

#[test]
fn the_same_value_in_text_and_binary_becomes_the_same_key() {
    for value in [0i64, 1, -1, 42, i64::MIN, i64::MAX] {
        let binary = canonical(Some(&value.to_be_bytes()), FORMAT_BINARY, KeyType::Int);
        let text = canonical(Some(value.to_string().as_bytes()), FORMAT_TEXT, KeyType::Int);
        assert_eq!(binary, text, "value {value}");
        assert_eq!(binary, Ok(OwnedKey::Int(value)));
    }
}

#[test]
fn a_uuid_is_the_same_key_in_either_format() {
    let raw: [u8; 16] = [
        0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00,
        0x00,
    ];
    let binary = canonical(Some(&raw), FORMAT_BINARY, KeyType::Uuid);
    let text = canonical(
        Some(b"550e8400-e29b-41d4-a716-446655440000"),
        FORMAT_TEXT,
        KeyType::Uuid,
    );
    assert_eq!(binary, Ok(OwnedKey::Uuid(raw)));
    assert_eq!(text, binary);
}

#[test]
fn a_null_key_is_refused() {
    assert_eq!(canonical(None, FORMAT_TEXT, KeyType::Int), Err(KeyError::Null));
    assert_eq!(canonical(None, FORMAT_BINARY, KeyType::Uuid), Err(KeyError::Null));
}

#[test]
fn a_malformed_key_is_an_error_not_a_guess() {
    assert!(canonical(Some(b"not a number"), FORMAT_TEXT, KeyType::Int).is_err());
    assert!(canonical(Some(&[1, 2, 3]), FORMAT_BINARY, KeyType::Int).is_err());
    assert!(canonical(Some(b"not-a-uuid"), FORMAT_TEXT, KeyType::Uuid).is_err());
    assert!(canonical(Some(&[0u8; 15]), FORMAT_BINARY, KeyType::Uuid).is_err());
}

#[test]
fn text_and_bytea_keys_pass_through_untouched() {
    assert_eq!(
        canonical(Some("علی".as_bytes()), FORMAT_TEXT, KeyType::Text),
        Ok(OwnedKey::Text("علی".to_owned()))
    );
    assert_eq!(
        canonical(Some(&[0u8, 0xFF]), FORMAT_BINARY, KeyType::Bytea),
        Ok(OwnedKey::Bytes(vec![0, 255]))
    );
}

#[test]
fn a_schema_change_has_to_reach_every_shard() {
    for sql in [
        "create table other (id int)",
        "truncate countries",
        "create index on countries (name)",
        "alter table countries add column x int",
        "create schema archive",
        "vacuum countries",
        "grant select on countries to app1",
    ] {
        match routing(sql) {
            Routing::EveryShard { .. } => {}
            other => panic!("{sql} names the whole cluster, got {other:?}"),
        }
    }
}

#[test]
fn what_the_session_takes_with_it_still_goes_to_one_backend() {
    for sql in [
        "create temp table scratch (id int)",
        "create temporary table scratch (id int)",
        "prepare p as select 1",
        "execute p",
        "deallocate p",
        "declare c cursor for select 1 from countries",
        "fetch 10 from c",
        "close c",
        "explain select 1",
        "discard all",
        "notify channel",
        "set constraints all deferred",
    ] {
        assert_eq!(routing(sql), Routing::NoShardedTable, "{sql}");
    }
}

#[test]
fn listen_cannot_hear_a_cluster_and_says_so() {
    for sql in ["listen channel", "unlisten channel", "unlisten *"] {
        match routing(sql) {
            Routing::EveryShard { .. } => {}
            other => panic!("{sql} cannot be answered by one shard, got {other:?}"),
        }
    }
}

#[test]
fn ddl_that_touches_a_sharded_table_is_refused() {
    for sql in ["truncate users", "alter table users add column x int", "drop table users"] {
        match routing(sql) {
            Routing::Unsupported(_) => {}
            other => panic!("{sql} should be refused, got {other:?}"),
        }
    }
}

fn refuses(sql: &str) -> &'static str {
    match routing(sql) {
        Routing::Unsupported(why) => why,
        other => panic!("{sql}\n  was not refused: {other:?}"),
    }
}

#[test]
fn an_integer_literal_wider_than_thirty_two_bits_is_still_a_key() {
    for (sql, expected) in [
        ("select * from users where id = 2147483647", 2_147_483_647i64),
        ("select * from users where id = 2147483648", 2_147_483_648),
        ("select * from users where id = -2147483648", -2_147_483_648),
        ("select * from users where id = 3000000000", 3_000_000_000),
        (
            "select * from users where id = 9223372036854775807",
            9_223_372_036_854_775_807,
        ),
    ] {
        assert_eq!(
            routing(sql),
            Routing::Single {
                source: KeySource::Int(expected),
                key_type: KeyType::Int,
            },
            "{sql}"
        );
    }
    assert_eq!(
        routing("insert into users(id, name) values (3000000000, 'a')"),
        Routing::Single {
            source: KeySource::Int(3_000_000_000),
            key_type: KeyType::Int,
        }
    );
}

#[test]
fn a_sharded_table_reached_through_a_subquery_is_refused() {
    for sql in [
        "select count(*) from (select id from users) s",
        "select count(*) from (select id from users where id = 7) s",
        "select (select name from users where id = 7)",
        "select * from orders o where o.user_id = 1 and exists (select 1 from users)",
    ] {
        assert!(
            refuses(sql).contains("subquery") || refuses(sql).contains("more than one"),
            "{sql} was refused for the wrong reason: {}",
            refuses(sql)
        );
    }
}

#[test]
fn a_with_clause_near_a_sharded_name_is_refused() {
    for sql in [
        "with s as (select id from users where id = 7) select * from s",
        "with users as (select 42 as id) select id from users",
        "with s as (select 1) select * from users where id = 7",
    ] {
        let _why = refuses(sql);
    }
}

#[test]
fn a_set_operation_over_a_sharded_table_is_refused() {
    for sql in [
        "select id from users where id = 1 union all select id from users where id = 2",
        "select id from users where id = 1 union select 2",
        "select id from users where id = 1 intersect select id from users where id = 1",
        "select id from users where id = 1 except select id from users where id = 2",
    ] {
        assert!(refuses(sql).contains("UNION"), "{sql}");
    }
    assert_eq!(routing("select 1 union all select 2"), Routing::NoShardedTable);
}

#[test]
fn assigning_to_the_sharding_key_is_refused() {
    assert!(refuses("update users set id = 9 where id = 1").contains("sharding key"));
    assert!(refuses("UPDATE users SET ID = 9, name = 'a' WHERE id = 1").contains("sharding key"));
    assert_eq!(
        routing("update users set name = 'a' where id = 1"),
        Routing::Single {
            source: KeySource::Int(1),
            key_type: KeyType::Int,
        }
    );
}

#[test]
fn a_statement_that_changes_the_connection_identity_is_refused() {
    for sql in [
        "set role app2",
        "SET ROLE app2",
        "set session authorization app2",
        "set local role app2",
    ] {
        let _why = refuses(sql);
    }
    assert_eq!(routing("set application_name = 'x'"), Routing::NoShardedTable);
    assert_eq!(routing("set timezone = 'UTC'"), Routing::NoShardedTable);
}

#[test]
fn an_order_by_shahrah_cannot_read_is_not_mergeable() {
    let unreadable = [
        "select id from users order by id * -1 limit 5",
        "select id from users order by 1 desc limit 5",
        "select id from users order by length(name) limit 5",
    ];
    for sql in unreadable {
        match analyse(sql, &policy()) {
            Ok(analysis) => assert!(!analysis.mergeable, "{sql} claimed to be mergeable"),
            Err(error) => panic!("{sql}: {error}"),
        }
    }
    match analyse("select id from users order by id limit 5", &policy()) {
        Ok(analysis) => assert!(analysis.mergeable, "a plain ORDER BY should merge"),
        Err(error) => panic!("{error}"),
    }
}

#[test]
fn touches_sharded_sees_what_analysis_cannot_route() {
    use shahrah_sql::analysis::touches_sharded;
    assert!(touches_sharded("select 1; select count(*) from users", &policy()));
    assert!(touches_sharded(
        "select 1; insert into users(id) values (7)",
        &policy()
    ));
    assert!(!touches_sharded("select 1; select 2", &policy()));
    assert!(!touches_sharded("this is not sql at all", &policy()));
}

#[test]
fn an_explicit_nulls_position_is_read_not_assumed() {
    let keys = |sql: &str| match analyse(sql, &policy()) {
        Ok(analysis) => analysis.order_by,
        Err(error) => panic!("{sql}: {error}"),
    };
    let first = |sql: &str| match keys(sql).first() {
        Some(key) => (key.descending, key.nulls_first),
        None => panic!("{sql} produced no order key"),
    };

    assert_eq!(first("select * from users order by id"), (false, false));
    assert_eq!(first("select * from users order by id desc"), (true, true));
    assert_eq!(
        first("select * from users order by id nulls first"),
        (false, true)
    );
    assert_eq!(
        first("select * from users order by id asc nulls last"),
        (false, false)
    );
    assert_eq!(
        first("select * from users order by id desc nulls last"),
        (true, false)
    );
    assert_eq!(
        first("select * from users order by id desc nulls first"),
        (true, true)
    );
}

#[test]
fn a_hint_wins_over_the_key_the_parser_can_see() {
    let decide = |sql: &str| match analyse(sql, &policy()) {
        Ok(analysis) => (analysis.routing, analysis.by_hint),
        Err(error) => panic!("{sql}: {error}"),
    };

    let (plain, by_hint) = decide("select * from users where id = 7");
    assert_eq!(
        plain,
        Routing::Single {
            source: KeySource::Int(7),
            key_type: KeyType::Int
        }
    );
    assert!(!by_hint);

    let (hinted, by_hint) = decide("/* shahrah: key=13 */ select * from users where id = 7");
    assert_eq!(
        hinted,
        Routing::Single {
            source: KeySource::Text("13".to_owned()),
            key_type: KeyType::Int
        }
    );
    assert!(by_hint, "the hint has to announce itself");

    let (pinned, by_hint) = decide("/* shahrah: shard=4 */ select * from users where id = 7");
    assert_eq!(pinned, Routing::Pinned { shard: 4 });
    assert!(by_hint);
}

#[test]
fn a_hint_shahrah_cannot_honour_is_an_error_never_a_guess() {
    let unroutable = |sql: &str| {
        matches!(
            analyse(sql, &policy()).map(|analysis| analysis.routing),
            Ok(Routing::Unsupported(_))
        )
    };

    assert!(unroutable("/* shahrah: tenant=7 */ select * from users where id = 1"));
    assert!(unroutable("/* shahrah: */ select * from users where id = 1"));
    assert!(unroutable("/* shahrah: shard=0 */ select 1"));
    assert!(unroutable("/* shahrah: shard=abc */ select 1"));
    assert!(unroutable("/* shahrah: shard=1 */ /* shahrah: shard=2 */ select 1"));
    assert!(unroutable("/* shahrah: shard=1 select 1"));
    assert!(
        unroutable("/* shahrah: key=7 */ select 1"),
        "a key hint with no sharded table has no key type to be read as, so it cannot be \
         quietly dropped"
    );
}

#[test]
fn a_comment_that_is_not_a_hint_changes_nothing() {
    let want = Routing::Single {
        source: KeySource::Int(7),
        key_type: KeyType::Int,
    };
    assert_eq!(routing("/* just a note */ select * from users where id = 7"), want);
    assert_eq!(routing("select * from users where id = 7 /* trailing */"), want);
    assert_eq!(routing("-- a line comment\nselect * from users where id = 7"), want);
}

#[test]
fn a_quoted_hint_value_carries_its_spaces_and_quotes() {
    let key = |sql: &str| match analyse(sql, &policy()) {
        Ok(Analysis {
            routing: Routing::Single {
                source: KeySource::Text(value),
                ..
            },
            ..
        }) => value,
        other => panic!("{sql}: {other:?}"),
    };
    assert_eq!(key("/* shahrah: key='ali reza' */ select * from names where id = 'x'"), "ali reza");
    assert_eq!(key("/* shahrah: key='it''s' */ select * from names where id = 'x'"), "it's");
    assert_eq!(key("/* shahrah: key=plain */ select * from names where id = 'x'"), "plain");
}

fn geo_policy() -> Policy {
    Policy::new()
        .with_key("users", "id", KeyType::Int)
        .with_replicated("plans", "na-east")
}

#[test]
fn a_table_gets_one_class_and_shahrah_will_not_pick_between_them() {
    let both = Policy::new()
        .with_key("users", "id", KeyType::Int)
        .with_replicated("users", "na-east");
    assert_eq!(
        both.check(&["na-east".to_owned()]),
        Err(PolicyError::TwoClasses {
            table: "users".to_owned()
        })
    );

    let ghost = Policy::new().with_replicated("plans", "oceania");
    assert_eq!(
        ghost.check(&["na-east".to_owned(), "eu-central".to_owned()]),
        Err(PolicyError::UnknownWriterRegion {
            table: "plans".to_owned(),
            region: "oceania".to_owned()
        })
    );

    let scattered = Policy::new()
        .with_replicated("plans", "na-east")
        .with_broadcast("plans");
    assert_eq!(
        scattered.check(&["na-east".to_owned()]),
        Err(PolicyError::ReplicatedBroadcast {
            table: "plans".to_owned()
        })
    );

    assert_eq!(geo_policy().check(&["na-east".to_owned()]), Ok(()));
}

#[test]
fn a_writer_region_is_only_checked_once_the_topology_names_regions() {
    let policy = Policy::new().with_replicated("plans", "oceania");
    assert_eq!(
        policy.check(&[]),
        Ok(()),
        "a topology that names no region cannot contradict a writer region"
    );
}

#[test]
fn the_class_of_every_table_a_statement_touches_is_reported() {
    let classes = |sql: &str| match analyse(sql, &geo_policy()) {
        Ok(analysis) => analysis.classes,
        Err(error) => panic!("{sql}: {error}"),
    };

    assert_eq!(
        classes("select * from users where id = 1"),
        vec![("users".to_owned(), Some(TableClass::GeoPartitioned))]
    );
    assert_eq!(
        classes("select * from plans"),
        vec![("plans".to_owned(), Some(TableClass::Replicated))]
    );
    assert_eq!(
        classes("select * from unknown_t"),
        vec![("unknown_t".to_owned(), None)],
        "a table with no class has to be reported as having none, not omitted"
    );
}

#[test]
fn a_schema_qualified_name_finds_the_same_policy_entry() {
    let policy = geo_policy();
    assert!(policy.is_sharded("public.users"));
    assert!(policy.is_replicated("public.plans"));
    assert_eq!(
        policy.class_of("public.users"),
        Some(TableClass::GeoPartitioned)
    );
    assert_eq!(policy.writer_region("public.plans"), Some("na-east"));
    match analyse("update public.users set name = 'x' where id = 1", &policy) {
        Ok(analysis) => assert_eq!(
            analysis.routing,
            Routing::Single {
                source: KeySource::Int(1),
                key_type: KeyType::Int
            },
            "a qualified write must not look like a write reaching a second table"
        ),
        Err(error) => panic!("qualified update did not analyse: {error}"),
    }
}

#[test]
fn one_statement_counts_what_the_lexer_sees_not_semicolons() {
    for sql in [
        "begin",
        "BEGIN;",
        "  begin  ;  ",
        "commit",
        "select 1",
        "select 'a;b'",
        "select $$a;b$$",
        "select 1 -- a comment with ; in it",
    ] {
        assert!(one_statement(sql), "{sql:?} is one statement");
    }
    for sql in [
        "begin; select 42; commit",
        "begin; select 42",
        "select 1; select 2",
        "commit; select 1",
        "select 'a;b'; select 2",
    ] {
        assert!(!one_statement(sql), "{sql:?} carries more than one statement");
    }
}

#[test]
fn text_the_lexer_cannot_read_is_not_treated_as_one_statement() {
    assert!(!one_statement(""));
    assert!(!one_statement("   "));
    assert!(!one_statement("select 'unterminated"));
}
