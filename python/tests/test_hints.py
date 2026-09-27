import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shahrah.hints import by_key, on_shard  # noqa: E402


def refused(call):
    try:
        call()
    except (TypeError, ValueError) as why:
        return str(why)
    return None


def test_a_hint_carries_what_shahrah_reads():
    assert by_key(7, "select 1") == "/* shahrah: key=7 */ select 1"
    assert by_key(-1, "select 1") == "/* shahrah: key=-1 */ select 1"
    assert by_key("ali", "select 1") == "/* shahrah: key=ali */ select 1"
    assert on_shard(3, "select 1") == "/* shahrah: shard=3 */ select 1"
    assert on_shard(65535, "select 1").startswith("/* shahrah: shard=65535 */")


def test_a_hint_shahrah_would_refuse_is_refused_here_instead():
    for call, why in [
        (lambda: by_key("", "x"), "an empty key"),
        (lambda: by_key("a*/b", "x"), "a key that closes the comment"),
        (lambda: by_key("a\nb", "x"), "a key with a newline"),
        (lambda: by_key(True, "x"), "a boolean key"),
        (lambda: by_key(1.5, "x"), "a float key"),
        (lambda: by_key(None, "x"), "no key"),
        (lambda: on_shard(0, "x"), "shard zero"),
        (lambda: on_shard(-2, "x"), "a negative shard"),
        (lambda: on_shard(65536, "x"), "a shard past the last one"),
        (lambda: on_shard(True, "x"), "a boolean shard"),
        (lambda: on_shard("2", "x"), "a shard as a string"),
    ]:
        assert refused(call) is not None, f"{why} was accepted"


if __name__ == "__main__":
    test_a_hint_carries_what_shahrah_reads()
    test_a_hint_shahrah_would_refuse_is_refused_here_instead()
    print("  python hint tests pass")
