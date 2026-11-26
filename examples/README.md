# Sample packets and queries

The `.hex` files are single-line hex dumps of complete mDNS response packets.
You can replay any of them with a tiny UDP sender:

```bash
# station-a (10.20.1.0/24) receives on udp/5353
python3 - <<'PY'
import socket
hexdata = open("examples/announce-a.hex").read().strip()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(bytes.fromhex(hexdata), ("127.0.0.1", 5353))
PY
```

Registering the same instance on both segments needs *two* packets, because
each segment is a separate UDP port: send `announce-a.hex` to 5353 and
`announce-b.hex` to 5354.

| file | purpose |
| --- | --- |
| `announce-a.hex` | PTR+SRV+A for "Front Desk" @ 10.20.1.10 on segment A |
| `announce-b.hex` | identical instance name @ 10.20.2.20 on segment B |
| `flush-only-a.hex` | only the A record, new address 10.20.1.99, cache-flush bit set (split refresh) |
| `goodbye-a.hex` | PTR+SRV+A with TTL=0 for the segment-A instance |

Queries:

```bash
curl -s 'http://127.0.0.1:8000/api/segments/station-a/services?service=_ipp._tcp.local.' | python3 -m json.tool
curl -s 'http://127.0.0.1:8000/api/services?segment=10.20.2.0%2F24' | python3 -m json.tool
curl -s 'http://127.0.0.1:8000/api/segments/station-a/records' | python3 -m json.tool
```

Expected sequence for the grace rules:

1. `announce-a.hex` -> query shows `Front Desk 10.20.1.10:631`, `remaining_ttl` ≈ 120.
2. `flush-only-a.hex` -> for one second the query returns both `.10` (with
   `"in_grace": true`) and `.99`; after that only `.99`.
3. `goodbye-a.hex` -> the instance stays queryable for one more second with
   `remaining_ttl` ≤ 1 and `in_grace: true`, then disappears.
4. Replaying `announce-a.hex` during either grace window cancels it and
   restores the full TTL.
