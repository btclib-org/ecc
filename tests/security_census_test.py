# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""SECURITY.md names every public function that hands libsecp256k1 a secret.

Its bullet on the Python around a crossing says what each such function
does with the secret in Python, before the call and after it. A function
added with a dispatch of its own and no line there leaves the bullet
naming less than its rule says, with nothing red. So this finds the
dispatches and their public entries in the source, and fails on an entry
the bullet's items do not name, unless `_PUBLIC_VALUES` below names it as
handing the bindings public values only.

A dispatch is a function whose body asks `_libsecp256k1_serves` or names
something imported from `ecc._libsecp256k1`. Its entries are the public
functions that reach it through private functions only: a public one
stops the walk, being an entry of its own. Calls are followed by name,
within a module and through the imports of `ecc` modules, and so are a
method reached through `self` and a class named in a call, which is its
`__init__`. A call through any other attribute, `ec.add_var` for one, is
not followed.

Whether an entry takes a secret is not read from the source. A `_var`
name and a verification are public by CONTRIBUTING.md's naming rules, and
are not asked for; any other entry is named in the bullet or in
`_PUBLIC_VALUES`, with its reason. What this does not check is the steps
the bullet gives for each name, which only reading the code can.
"""

import ast
from pathlib import Path

_ROOT = Path(__file__).parents[1]
_SRC = _ROOT / "src"
_SECURITY = _ROOT / "SECURITY.md"
_BULLET = "- **the Python around a crossing"
# the first item of that bullet, past its opening paragraphs
_ITEM = "\n    - "

# entries reached only with public values, and what those values are
_PUBLIC_VALUES = {
    "ecc.curves.curve.set_libsecp256k1_serving": "a switch, and no key",
    "ecc.curves.curve.TweakChain.__init__": "a public base point",
    "ecc.curves.curve.TweakChain.point": "a public tweak of that point",
    "ecc.curves.sec_point.PubKeyTweakChain.__init__": "a public key",
    "ecc.ecc.dsa.recover_pub_key_": "a signature and a message hash",
    "ecc.ecc.dsa.recover_pub_keys_": "a signature and a message hash",
    "ecc.ecc.dsa.recover_sec_": "a signature and a message hash",
    "ecc.ecc.ssa.anti_exfil_sign": (
        "its key reaches `bip340_nonce_` and its nonce `commit_nonce_`; its"
        " own dispatches are handed public values only, x-coordinates to"
        " lift and its signature to verify"
    ),
    "ecc.ecc.ssa.anti_exfil_signer_commit": (
        "its key reaches `bip340_nonce_`; its own dispatches are handed"
        " public values only, x-coordinates to lift"
    ),
}


def _module_name(path: Path) -> str:
    """Return the dotted name of a module of the package."""
    parts = path.relative_to(_SRC).with_suffix("").parts
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


class _Package:
    """The package's functions, its imports, and who calls whom."""

    def __init__(self) -> None:
        self.functions: dict[str, ast.FunctionDef] = {}
        self.owner: dict[str, str] = {}
        self.imports: dict[str, dict[str, str]] = {}
        self.bindings: dict[str, set[str]] = {}
        self.public: set[str] = set()
        exported: dict[str, list[str]] = {}
        for path in sorted(_SRC.rglob("*.py")):
            module = _module_name(path)
            tree = ast.parse(path.read_text(encoding="utf-8"))
            self.imports[module] = {}
            self.bindings[module] = set()
            for node in tree.body:
                self._read(module, node, exported)
        for module, names in exported.items():
            for name in names:
                prefix = f"{module}.{name}"
                self.public |= {
                    q
                    for q in self.functions
                    if self.owner[q] == module
                    and (q == prefix or q.startswith(prefix + "."))
                    and (
                        not q.rsplit(".", 1)[1].startswith("_")
                        or q.endswith(".__init__")
                    )
                }

    def _read(
        self, module: str, node: ast.stmt, exported: dict[str, list[str]]
    ) -> None:
        """Record what one top-level statement defines or imports."""
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("ecc"):
            for alias in node.names:
                local = alias.asname or alias.name
                if node.module == "ecc._libsecp256k1":
                    self.bindings[module].add(local)
                else:
                    self.imports[module][local] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Assign) and ast.unparse(node.targets[0]) == "__all__":
            exported[module] = ast.literal_eval(node.value)
        elif isinstance(node, ast.FunctionDef):
            self.functions[f"{module}.{node.name}"] = node
            self.owner[f"{module}.{node.name}"] = module
        elif isinstance(node, ast.ClassDef):
            for member in node.body:
                if isinstance(member, ast.FunctionDef):
                    name = f"{module}.{node.name}.{member.name}"
                    self.functions[name] = member
                    self.owner[name] = module

    def resolve(self, module: str, name: str) -> str | None:
        """Return the function a name stands for in a module, if any.

        A class stands for its `__init__`, and an imported name is followed
        through the modules that re-export it. A module is a name too, and
        `from ecc import curves` names one the package imports back, so
        a target already visited ends the search.
        """
        target = f"{module}.{name}"
        visited = set()
        while (
            target not in self.functions and target + ".__init__" not in self.functions
        ):
            source, _, local = target.rpartition(".")
            if target in visited or local not in self.imports.get(source, {}):
                return None
            visited.add(target)
            target = self.imports[source][local]
        return target if target in self.functions else target + ".__init__"

    def callees(self, qualified: str) -> set[str]:
        """Return the package functions a function names in its body."""
        module = self.owner[qualified]
        found: set[str | None] = set()
        for node in ast.walk(self.functions[qualified]):
            if isinstance(node, ast.Name):
                found.add(self.resolve(module, node.id))
            elif isinstance(node, ast.Attribute) and ast.unparse(node.value) == "self":
                method = f"{qualified.rsplit('.', 1)[0]}.{node.attr}"
                found.add(method if method in self.functions else None)
        return {name for name in found if name is not None and name != qualified}

    def is_dispatch(self, qualified: str) -> bool:
        """Return True where the function asks for or calls the bindings."""
        names = {
            node.id
            for node in ast.walk(self.functions[qualified])
            if isinstance(node, ast.Name)
        }
        return "_libsecp256k1_serves" in names or bool(
            names & self.bindings[self.owner[qualified]]
        )


def _entries() -> set[str]:
    """Return each public function reaching a dispatch through private ones."""
    package = _Package()
    callers: dict[str, set[str]] = {}
    for function in package.functions:
        for callee in package.callees(function):
            callers.setdefault(callee, set()).add(function)
    entries = set()
    todo = [f for f in package.functions if package.is_dispatch(f)]
    seen = set()
    while todo:
        function = todo.pop()
        if function in seen:
            continue
        seen.add(function)
        if function in package.public:
            entries.add(function)
        else:
            todo += callers.get(function, ())
    return entries


def _is_public_by_name(entry: str) -> bool:
    """Return True for a `_var` name and for a verification."""
    name = entry.rsplit(".", 1)[1]
    return name.rstrip("_").endswith("_var") or (
        name.startswith(("assert_", "is_", "check_")) or "verify" in name
    )


def _census() -> set[tuple[str, ...]]:
    """Return the dotted names the bullet's items spell, split into parts.

    The items only: the paragraphs above them name a function that is not
    listed, `dsa.gen_keys`, as an example, and the helpers the items
    share, and neither is a listing.
    """
    text = _SECURITY.read_text(encoding="utf-8")
    start = text.index(_ITEM, text.index(_BULLET))
    end = text.find("\n- ", start)
    spans = text[start:end].split("`")[1::2]
    return {tuple(span.split(".")) for span in spans if "." in span and " " not in span}


def _named(entry: str, census: set[tuple[str, ...]]) -> bool:
    """Return True where the bullet names the entry or the class it is in."""
    parts = tuple(entry.split("."))
    return any(
        name in (parts[-len(name) :], parts[-len(name) - 1 : -1]) for name in census
    )


def test_every_entry_holding_a_secret_is_in_the_census() -> None:
    """An entry is named in SECURITY.md's bullet, or hands public values."""
    census = _census()
    missing = sorted(
        entry
        for entry in _entries()
        if not _is_public_by_name(entry)
        and entry not in _PUBLIC_VALUES
        and not _named(entry, census)
    )
    assert not missing, f"not in SECURITY.md's census: {missing}"


def test_every_public_value_entry_is_still_an_entry() -> None:
    """A name in `_PUBLIC_VALUES` is an entry the walk still finds.

    A renamed function, or one that no longer reaches a dispatch, would
    otherwise sit in the table excusing nothing.
    """
    assert set(_PUBLIC_VALUES) <= _entries()


def test_the_walk_finds_the_entries_it_is_written_for() -> None:
    """The walk reaches a dispatch through a private twin and through a class.

    `curves.mult` reaches `_mult_checked`, `ecies.derive_keys` reaches
    `sec_point._mult_sec_compressed` across modules, and `dsa.Signer.sign_`
    reaches its dispatch through `self`. A walk that found none of them would
    make the census test above pass on an empty set. And a name the bullet
    spells only above its items, an example or a shared helper, is not
    read as listed, or such a function would pass the census unlisted.
    """
    entries = _entries()
    assert {
        "ecc.curves.curve.mult",
        "ecc.ecc.ecies.derive_keys",
        "ecc.ecc.dsa.Signer.sign_",
        "ecc.ecc.pedersen.commit",
    } <= entries
    assert "ecc.ecc.musig2.sign" not in entries
    census = _census()
    assert _named("ecc.ecc.dsa.Signer.__init__", census)
    # named above the items, as an example and as a shared helper
    assert not _named("ecc.ecc.dsa.gen_keys", census)
    assert not _named("ecc.curves.sec_point.scalar_from_prv_key", census)
    assert not _named("ecc.ecc.dsa.sign_", {("ssa", "sign_")})
