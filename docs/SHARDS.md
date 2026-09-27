# Shards

Two numbers decide how this system grows: how many logical shards there are, and
how many databases they sit on. Only the second one is allowed to change.

## The indirection

A key does not hash to a database. It hashes to one of 65536 **logical shards**,
and a separate map says which database owns each logical shard.

The map is the whole point. Adding a database rewrites map entries; it never
rewrites a hash. Only the rows in the moved entries go anywhere. Without the
indirection, hashing directly to N databases means every added database rehashes
every row in the system — the migration this layer exists to make unnecessary.

## Why 65536

The logical shard count is not a capacity limit. It is the size of the smallest
piece of data that can be moved.

One logical shard is 1/65536 of the dataset. At 10^11 rows that is about 1.5
million rows — small enough to copy to another database while the system is
serving traffic, and small enough that if a move goes wrong, the blast radius is
1.5 million rows and not the whole table.

`mirazhe` uses 1024. The same 10^11 rows would make one shard about 98 million
rows. Nothing moves 98 million rows online. A count that coarse turns every
rebalance into a maintenance window, which in practice means rebalancing never
happens and the largest database keeps growing.

Going the other way costs nothing worth having. The map is a flat array of 65536
two-byte entries: 128 KiB, resident in L2, measured at 1.4 ns for a hot lookup
and 2.5 ns for one scattered across the whole map. Key to physical shard, hash
included, is 6.3 ns. A finer-grained map would not buy a smaller move that
anybody needs.

**This number can never change once real data exists.** Changing it moves every
row in the system at once. Treat it exactly like the hash: a frozen contract.

## Why the logical id is a `u16`

65536 is the count *because* it is the full range of a `u16`, not by coincidence.

Every `u16` is a valid logical shard. The conversion from a hash to a shard is
total: no mask that can fold an out-of-range value onto a real one, no clamp, no
`Result` for a case that cannot occur, no branch on the hot path. `LogicalShard`
can be constructed from any `u16` and the compiler knows the index is in bounds,
so the map lookup is a single load with no bounds check.

The alternative is visible in `mirazhe`, where 1024 shards are stored in a `u16`.
Values from 1024 to 65535 are representable but meaningless, and the mask that
hides them silently sends shard 1024 to shard 0. Making the type exactly as wide
as the domain deletes that entire class of bug rather than guarding against it.

## Why the physical id is a `NonZeroU16` numbered from 1

A map under construction has to tell "this logical shard belongs to database 4"
apart from "nobody has said yet". If zero were a valid database number, a
half-written configuration would quietly route a third of the traffic to database
zero instead of failing.

Numbering databases from 1 makes zero mean nothing, and `NonZeroU16` makes the
compiler enforce it. It also makes the enforcement free: `Option<PhysicalShard>`
uses the zero bit pattern for `None`, so a slot that is still empty takes the same
two bytes as a filled one, and the builder for a complete map is the same 128 KiB
as the map itself.

The completed `ShardMap` holds no `Option` at all. Every logical shard is checked
to have a physical shard once, when the map is built, and a map with a hole cannot
be constructed. Past that point "every shard has a home" is a property of the
type, not a convention, and lookup has nothing to decide.

Ceiling: 65535 databases. At that point one database owns one logical shard and
the design has other problems.

## What is meant to change

How many databases exist. That number is expected to start at one or two and grow.
Adding one rewrites map entries and moves the rows those entries point at, and
nothing else in this document moves with it.
