# bench/geo

Three regions with the real distances shaped in, a proxy in each, and the same
users served two ways: from their own region, or from one region for everyone.

```bash
docker compose up -d --wait
python3 harness.py
```

The distance is a property of the **pair**, not of the database: each proxy
installs a `netem` band per far region and a filter on that region's address, so
`geo-eu` is 42 ms from `pgna` and 110 ms from `pgasia` while its own `pgeu` is
local. That is what a sidecar deployment looks like, and it is the only geometry
in which the question means anything — shaping the databases instead would make
every proxy equally far from everything.

The first version of this bed did shape the databases, and the first numbers it
produced said a single region was *faster* than placing data by region. The
priomap was also wrong, so the unclassified band carried the 42 ms delay and even
a local read paid it. Both were caught by asking the obvious question: why is a
read from a proxy to the database beside it taking 86 ms?
