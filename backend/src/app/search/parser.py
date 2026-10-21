"""Hunt query language → AST. Hand-written recursive descent; no SQL is ever built from text.

    user:admin AND outcome:failure AND src_ip:10.0.*
    (action:logon OR action:ssh_login) NOT user:root
    http_status:>=400 "Failed password" -host:web02

Grammar:   expr   := or
           or     := and ( OR and )*
           and    := unary ( [AND] unary )*          (adjacent terms are ANDed)
           unary  := (NOT | '-') unary | atom
           atom   := '(' expr ')' | FIELD ':' [OP] VALUE | VALUE        (bare VALUE = free text)
"""

from dataclasses import dataclass
from typing import Literal

MAX_QUERY_CHARS = 1000
MAX_NODES = 100
MAX_DEPTH = 20

Op = Literal["eq", "gte", "gt", "lte", "lt"]


class SearchError(ValueError):
    def __init__(self, message: str, pos: int = 0) -> None:
        super().__init__(message)
        self.message = message
        self.pos = pos


@dataclass(frozen=True, slots=True)
class Term:
    field: str
    op: Op
    value: str


@dataclass(frozen=True, slots=True)
class Text:
    value: str


@dataclass(frozen=True, slots=True)
class Not:
    child: "Node"


@dataclass(frozen=True, slots=True)
class And:
    children: tuple["Node", ...]


@dataclass(frozen=True, slots=True)
class Or:
    children: tuple["Node", ...]


Node = Term | Text | Not | And | Or


@dataclass(frozen=True, slots=True)
class Tok:
    kind: str  # LPAREN RPAREN AND OR NOT MINUS WORD STRING
    text: str
    pos: int
    colon: int = -1  # index of the field/value colon inside an unquoted WORD
    quoted_value: bool = False


_STOP = set(' \t\r\n()"')


def tokenize(q: str) -> list[Tok]:
    if len(q) > MAX_QUERY_CHARS:
        raise SearchError(f"query is longer than {MAX_QUERY_CHARS} characters")
    toks: list[Tok] = []
    i, n = 0, len(q)
    while i < n:
        c = q[i]
        if c in " \t\r\n":
            i += 1
        elif c == "(":
            toks.append(Tok("LPAREN", c, i))
            i += 1
        elif c == ")":
            toks.append(Tok("RPAREN", c, i))
            i += 1
        elif c == '"':
            j, buf = i + 1, []
            while j < n and q[j] != '"':
                if q[j] == "\\" and j + 1 < n:
                    j += 1
                buf.append(q[j])
                j += 1
            if j >= n:
                raise SearchError("unterminated quote", i)
            toks.append(Tok("STRING", "".join(buf), i))
            i = j + 1
        else:
            j = i
            colon = -1
            while j < n and q[j] not in _STOP:
                if q[j] == ":" and colon < 0:
                    colon = j - i
                    # field:"quoted value"
                    if j + 1 < n and q[j + 1] == '"':
                        k, buf = j + 2, []
                        while k < n and q[k] != '"':
                            if q[k] == "\\" and k + 1 < n:
                                k += 1
                            buf.append(q[k])
                            k += 1
                        if k >= n:
                            raise SearchError("unterminated quote", j + 1)
                        toks.append(Tok("WORD", q[i:j] + ":" + "".join(buf), i, colon, True))
                        i = k + 1
                        break
                j += 1
            else:
                word = q[i:j]
                upper = word.upper()
                if upper in ("AND", "OR", "NOT") and colon < 0:
                    toks.append(Tok(upper, word, i))
                elif word.startswith("-") and len(word) > 1:
                    toks.append(Tok("MINUS", "-", i))
                    toks.append(Tok("WORD", word[1:], i + 1, colon - 1 if colon >= 0 else -1))
                else:
                    toks.append(Tok("WORD", word, i, colon))
                i = j
                continue
            continue
    return toks


class _Parser:
    def __init__(self, toks: list[Tok]) -> None:
        self.t = toks
        self.i = 0
        self.nodes = 0

    def peek(self) -> Tok | None:
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self) -> Tok:
        tok = self.t[self.i]
        self.i += 1
        return tok

    def count(self) -> None:
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise SearchError(f"query has more than {MAX_NODES} terms")

    def parse(self) -> Node:
        node = self.or_(0)
        if (tok := self.peek()) is not None:
            raise SearchError(
                "unexpected " + ("')'" if tok.kind == "RPAREN" else repr(tok.text)), tok.pos
            )
        return node

    def or_(self, depth: int) -> Node:
        items = [self.and_(depth)]
        while (p := self.peek()) and p.kind == "OR":
            self.take()
            items.append(self.and_(depth))
        return items[0] if len(items) == 1 else Or(tuple(items))

    def and_(self, depth: int) -> Node:
        items = [self.unary(depth)]
        while (p := self.peek()) and p.kind not in ("OR", "RPAREN"):
            if p.kind == "AND":
                self.take()
            items.append(self.unary(depth))
        return items[0] if len(items) == 1 else And(tuple(items))

    def unary(self, depth: int) -> Node:
        p = self.peek()
        if p is None:
            raise SearchError(
                "expected a search term at end of query", len(self.t) and self.t[-1].pos
            )
        if p.kind in ("NOT", "MINUS"):
            self.take()
            self.count()
            return Not(self.unary(depth))
        return self.atom(depth)

    def atom(self, depth: int) -> Node:
        tok = self.take()
        if tok.kind == "LPAREN":
            if depth + 1 > MAX_DEPTH:
                raise SearchError("parentheses nested too deeply", tok.pos)
            node = self.or_(depth + 1)
            if (p := self.peek()) is None or p.kind != "RPAREN":
                raise SearchError("missing ')'", tok.pos)
            self.take()
            return node
        self.count()
        if tok.kind == "STRING":
            return Text(tok.text)
        if tok.kind == "WORD":
            if tok.colon > 0:
                field = tok.text[: tok.colon].lower()
                rest = tok.text[tok.colon + 1 :]
                if not rest:
                    raise SearchError(f"{field}: needs a value", tok.pos)
                op: Op = "eq"
                if not tok.quoted_value:
                    for prefix, o in ((">=", "gte"), ("<=", "lte"), (">", "gt"), ("<", "lt")):
                        if rest.startswith(prefix):
                            op, rest = o, rest[len(prefix) :]  # type: ignore[assignment]
                            break
                    if not rest:
                        raise SearchError(f"{field}: needs a value after the operator", tok.pos)
                return Term(field, op, rest)
            return Text(tok.text)
        raise SearchError(f"unexpected {tok.text!r}", tok.pos)


def parse(query: str) -> Node | None:
    """Empty query → None (match everything)."""
    toks = tokenize(query)
    if not toks:
        return None
    return _Parser(toks).parse()
