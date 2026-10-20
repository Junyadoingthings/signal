"""Entity and relationship extraction for the entity pages and graph.

Entities: host, user, ip, process, domain. DNS names are reduced to their registered
domain, so a tunnel spraying thousands of unique subdomains is one entity, not thousands.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from app.ingest.types import NormalizedEvent
from app.storage.models import EntityType

# Small, explicit list of two-label public suffixes; good enough for grouping.
_TWO_LABEL_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "co.za",
    "org.za",
    "gov.za",
    "ac.za",
    "com.au",
    "net.au",
    "org.au",
    "co.nz",
    "co.jp",
    "com.br",
    "com.cn",
    "com.mx",
    "co.in",
    "co.kr",
}

INBOUND_ACTIONS = {"logon", "ssh_login", "ssh_invalid_user", "pam_auth_failure", "http_request"}


def registered_domain(name: str) -> str:
    labels = [x for x in name.lower().rstrip(".").split(".") if x]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


EntityKey = tuple[EntityType, str]
EdgeKey = tuple[EntityKey, EntityKey, str]


@dataclass(slots=True)
class Seen:
    first: datetime
    last: datetime
    count: int = 0

    def add(self, ts: datetime) -> None:
        self.first = min(self.first, ts)
        self.last = max(self.last, ts)
        self.count += 1


def entities_of(ev: NormalizedEvent) -> tuple[list[EntityKey], list[EdgeKey]]:
    ents: list[EntityKey] = []
    edges: list[EdgeKey] = []
    host = (EntityType.host, ev.host) if ev.host else None
    user = (EntityType.user, ev.user) if ev.user else None
    proc = (EntityType.process, ev.process_name) if ev.process_name else None
    src = (EntityType.ip, ev.src_ip) if ev.src_ip else None
    dst = (EntityType.ip, ev.dst_ip) if ev.dst_ip else None
    dom = (EntityType.domain, registered_domain(ev.dns_query)) if ev.dns_query else None

    for e in (host, user, proc, src, dst, dom):
        if e is not None:
            ents.append(e)

    if user and host:
        edges.append((user, host, "active_on"))
    if proc and host:
        edges.append((host, proc, "ran"))
    if proc and user:
        edges.append((user, proc, "ran"))
    if host and dom:
        edges.append((host, dom, "resolved"))
    if ev.action == "network_connection":
        if host and dst:
            edges.append((host, dst, "connected_to"))
        if proc and dst:
            edges.append((proc, dst, "connected_to"))
    elif src and host and (ev.action in INBOUND_ACTIONS or ev.source_type == "web_access"):
        edges.append((src, host, "connected_to"))
        if user:
            edges.append((src, user, "authenticated_as"))
    return ents, edges


def aggregate(
    events: Iterable[NormalizedEvent],
) -> tuple[dict[EntityKey, Seen], dict[EdgeKey, Seen]]:
    ents: dict[EntityKey, Seen] = {}
    edges: dict[EdgeKey, Seen] = {}
    for ev in events:
        e_keys, d_keys = entities_of(ev)
        for k in set(e_keys):
            ents.setdefault(k, Seen(ev.timestamp, ev.timestamp)).add(ev.timestamp)
        for d in set(d_keys):
            edges.setdefault(d, Seen(ev.timestamp, ev.timestamp)).add(ev.timestamp)
    return ents, edges
