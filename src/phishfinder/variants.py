from __future__ import annotations

from dataclasses import dataclass
import re


COMMON_PUBLIC_SUFFIXES = (
    "co.jp",
    "ne.jp",
    "or.jp",
    "ac.jp",
    "go.jp",
    "ed.jp",
    "gr.jp",
    "lg.jp",
)
DEFAULT_INSERTIONS = ("s", "x", "1", "p", "0", "n", "m", "r", "e", "a")
DEFAULT_KEYWORDS = (
    "login",
    "secure",
    "security",
    "support",
    "account",
    "verify",
    "id",
    "auth",
    "pay",
    "payment",
    "billing",
    "card",
    "mail",
    "web",
    "portal",
    "mypage",
    "member",
    "customer",
    "service",
    "help",
    "claim",
    "notice",
    "update",
    "confirm",
)
DEFAULT_TLDS = (
    "com",
    "jp",
    "co.jp",
    "ne.jp",
    "net",
    "org",
    "co",
    "info",
    "biz",
    "site",
    "online",
    "shop",
    "xyz",
    "top",
)
DEFAULT_SUBSTITUTIONS = {
    "a": ("4", "@"),
    "e": ("3",),
    "i": ("1", "l"),
    "l": ("1", "i"),
    "o": ("0",),
    "s": ("5",),
    "t": ("7",),
    "g": ("9",),
    "b": ("8",),
}
KEYBOARD_NEIGHBORS = {
    "a": ("q", "w", "s", "z"),
    "b": ("v", "g", "h", "n"),
    "c": ("x", "d", "f", "v"),
    "d": ("s", "e", "r", "f", "c", "x"),
    "e": ("w", "s", "d", "r"),
    "f": ("d", "r", "t", "g", "v", "c"),
    "g": ("f", "t", "y", "h", "b", "v"),
    "h": ("g", "y", "u", "j", "n", "b"),
    "i": ("u", "j", "k", "o"),
    "j": ("h", "u", "i", "k", "m", "n"),
    "k": ("j", "i", "o", "l", "m"),
    "l": ("k", "o", "p"),
    "m": ("n", "j", "k"),
    "n": ("b", "h", "j", "m"),
    "o": ("i", "k", "l", "p"),
    "p": ("o", "l"),
    "q": ("w", "a"),
    "r": ("e", "d", "f", "t"),
    "s": ("a", "w", "e", "d", "x", "z"),
    "t": ("r", "f", "g", "y"),
    "u": ("y", "h", "j", "i"),
    "v": ("c", "f", "g", "b"),
    "w": ("q", "a", "s", "e"),
    "x": ("z", "s", "d", "c"),
    "y": ("t", "g", "h", "u"),
    "z": ("a", "s", "x"),
}
DEFAULT_HOMOGRAPHS = {
    "a": ("а",),  # キリル文字の小文字a
    "e": ("е",),  # キリル文字の小文字ie
    "o": ("о",),  # キリル文字の小文字o
    "p": ("р",),  # キリル文字の小文字er
    "c": ("с",),  # キリル文字の小文字es
    "x": ("х",),  # キリル文字の小文字ha
}


@dataclass(frozen=True)
class VariantConfig:
    insertions: tuple[str, ...] = DEFAULT_INSERTIONS
    keywords: tuple[str, ...] = DEFAULT_KEYWORDS
    tlds: tuple[str, ...] = DEFAULT_TLDS
    substitutions: dict[str, tuple[str, ...]] | None = None
    keyboard_neighbors: dict[str, tuple[str, ...]] | None = None
    homographs: dict[str, tuple[str, ...]] | None = None
    include_idn: bool = True


def split_domain(domain: str) -> tuple[str, str]:
    labels = domain.strip().lower().rstrip(".").split(".")
    if len(labels) < 2 or not labels[-2] or not labels[-1]:
        raise ValueError(f"Expected a registrable domain like example.com: {domain!r}")
    suffix = ".".join(labels[-2:])
    if suffix in COMMON_PUBLIC_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[:-2]), suffix
    return ".".join(labels[:-1]), labels[-1]


def to_ascii_domain(domain: str) -> str:
    return domain.encode("idna").decode("ascii")


def _is_valid_ascii_domain(domain: str) -> bool:
    if len(domain) > 253:
        return False
    for label in domain.split("."):
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not re.fullmatch(r"[a-z0-9-]+", label):
            return False
    return True


def _add_variant(variants: set[str], name: str, suffix: str) -> None:
    domain = f"{name}.{suffix}".lower()
    if _is_valid_ascii_domain(domain):
        variants.add(domain)


def _without_separators(name: str) -> str:
    return name.replace("-", "").replace(".", "")


def generate_variants(seed_domain: str, config: VariantConfig | None = None) -> list[str]:
    config = config or VariantConfig()
    substitutions = config.substitutions or DEFAULT_SUBSTITUTIONS
    keyboard_neighbors = config.keyboard_neighbors or KEYBOARD_NEIGHBORS
    homographs = config.homographs or DEFAULT_HOMOGRAPHS
    name, suffix = split_domain(seed_domain)
    variants: set[str] = set()

    for index in range(len(name)):
        _add_variant(variants, name[:index] + name[index + 1 :], suffix)

    for index in range(len(name) + 1):
        for char in config.insertions:
            _add_variant(variants, name[:index] + char + name[index:], suffix)

    for index, char in enumerate(name):
        if char.isalnum():
            _add_variant(variants, name[:index] + char + name[index:], suffix)

    for index in range(len(name) - 1):
        if name[index] != name[index + 1]:
            swapped = name[:index] + name[index + 1] + name[index] + name[index + 2 :]
            _add_variant(variants, swapped, suffix)

    for index, char in enumerate(name):
        for replacement in substitutions.get(char, ()):
            _add_variant(variants, name[:index] + replacement + name[index + 1 :], suffix)
        for replacement in keyboard_neighbors.get(char, ()):
            _add_variant(variants, name[:index] + replacement + name[index + 1 :], suffix)
        if config.include_idn:
            for replacement in homographs.get(char, ()):
                unicode_domain = name[:index] + replacement + name[index + 1 :] + "." + suffix
                try:
                    variants.add(to_ascii_domain(unicode_domain))
                except UnicodeError:
                    continue

    compact_name = _without_separators(name)
    if compact_name != name:
        _add_variant(variants, compact_name, suffix)
    if "-" not in name and len(name) >= 4:
        midpoint = len(name) // 2
        _add_variant(variants, f"{name[:midpoint]}-{name[midpoint:]}", suffix)

    for keyword in config.keywords:
        _add_variant(variants, f"{name}-{keyword}", suffix)
        _add_variant(variants, f"{keyword}-{name}", suffix)
        _add_variant(variants, f"{name}{keyword}", suffix)
        _add_variant(variants, f"{keyword}{name}", suffix)

    for new_tld in config.tlds:
        if new_tld != suffix:
            _add_variant(variants, name, new_tld)

    variants.discard(seed_domain.strip().lower().rstrip("."))
    return sorted(variants)
