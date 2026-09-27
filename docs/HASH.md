# The shard hash

This file defines how a value becomes a shard number. Everything in it is frozen.
Changing any of it changes where existing rows live, which means moving all of
them — so treat this as a contract, not as documentation.

## The short version

Turn the value into bytes the canonical way, hash the bytes with XXH3-64, keep the
low 16 bits. That number is the logical shard, 0 to 65535.

## The algorithm

XXH3-64, as frozen in xxHash 0.8.0. No seed, no custom secret — the plain one-shot
function. Any library implementing the final XXH3 spec will agree. Libraries older
than 0.8.0 will not, because the algorithm was still changing before that release.

That agreement is not taken on trust. On 2026-08-21 the Rust crate this project
uses, `xxhash-rust` 0.8.18, was checked against two builds of Yann Collet's C
reference — the `xxhash` Python package over libxxhash 0.8.3, and the `xxhsum`
0.8.2 command-line tool — over inputs placed on both sides of every one of XXH3's
internal length boundaries, which is where a reimplementation drifts if it is
going to. All three agreed exactly.

## Canonical encoding

The proxy reads values off the PostgreSQL wire, where the same value arrives as
text or as binary depending on the client library. Never hash what arrived on the
wire. Convert first:

| Type | Bytes that get hashed |
|---|---|
| smallint, integer, bigint | widen to a signed 64-bit integer, then its 8 bytes, little-endian |
| oid | widen unsigned to 64-bit, then as above |
| text, varchar, char | the UTF-8 bytes, exactly as they are |
| uuid | the 16 raw bytes — not the hyphenated string |
| bytea | the bytes, as they are |

Little-endian was an arbitrary choice. It is frozen now; do not "fix" it.

Signed and unsigned widening are different rules and they produce different keys
from the same bits: `-1::int4` and `4294967295::oid` are both `ffffffff` on the
wire and are not the same key.

Three consequences worth saying out loud. `42::int4` and `42::int8` are the same
key. A uuid stored as text is *not* the same key as that uuid in a uuid column —
declare the column type honestly. And the type name is not itself part of what gets
hashed, so two values of different types whose canonical bytes coincide land on the
same shard: a bytea holding the three bytes of `ali` shares a shard with the text
`ali`. That is harmless, because a column has exactly one type and every table
shards on its own key, but it is a property of this design rather than an accident,
and `vectors.tsv` pins it as one.

## What cannot be a sharding key

- `real`, `double precision` — values that compare equal can have different bit
  patterns, and NaN is not equal to itself.
- `numeric` — 1.0 and 1.00 are one number with two representations.
- NULL — a row whose key is unknown has no home.

These are refused, never coerced.

## Normalization is not done here

Lowercasing an email, trimming whitespace, turning a phone number into E.164 —
none of that happens in this layer. Those rules belong to the application and
differ per column. This layer hashes the bytes it is handed.

## Getting the shard number

Keep the low 16 bits of the 64-bit hash. Because there are exactly 65536 logical
shards, every 16-bit value is a valid shard and this conversion can never fail.

## Versioning

Every hash carries a version tag. Only V1 exists today, and it is what this file
describes. If a V2 ever arrives, V1 stays here untouched — old data keeps
resolving the old way while new data uses the new one.

## Composite keys

Not implemented. When they arrive, each part is encoded canonically and prefixed
with its length before being concatenated, so that ("ab", "c") and ("a", "bc")
cannot produce the same bytes. Reserving the rule now keeps the choice
unambiguous later.

## One thing this hash does not do

XXH3 is fast, not adversarial. Anyone who can freely choose sharding keys can work
out offline which keys land together and deliberately overload a single shard.
This is accepted: sharding keys are normally server-assigned ids, and the worst
case is uneven load, never lost or incorrect data. If a table genuinely shards on
a user-chosen string, shard it on an internal id instead.

## Test vectors

`vectors.tsv` sits next to this file and holds one case per line, tab-separated,
in six columns:

| Column | Meaning |
|---|---|
| `version` | the hash version tag; only `1` exists |
| `type` | the PostgreSQL type of the key |
| `value` | the input in the natural form for that type: decimal for the integer types, the hyphenated lowercase form for uuid, lowercase hex of the raw bytes for text and bytea |
| `canonical` | lowercase hex of the exact bytes handed to XXH3-64 |
| `hash` | the 64-bit result, sixteen lowercase hex digits |
| `shard` | the low 16 bits of `hash`, in decimal |

Blank lines and lines beginning with `#` are skipped. The comments group the cases
by which rule each group holds down.

The file was generated once from the C reference implementation, with the encoding
rules above applied independently of `crates/hash`, and then frozen. That direction
matters. A vector file generated from the implementation it tests can only prove
that the implementation has not changed; this one also checks that the code agrees
with this document.

`value` deliberately carries the un-encoded form, so that producing the canonical
bytes is part of what gets tested rather than something the file hands over.
`canonical` is redundant for a passing test and invaluable for a failing one: it
says whether the encoding moved or the hash did.

A red vector test never means the file needs regenerating. It means the code
changed, and every row already written is now addressed wrongly. The Rust tests
read this file, and an implementation in another language should read the same one.