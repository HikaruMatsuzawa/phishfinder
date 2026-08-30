from __future__ import annotations

from dataclasses import dataclass


DEFAULT_INSERTIONS = ("s", "x", "1", "p")
DEFAULT_KEYWORDS = ("login", "secure", "support", "account", "verify")
DEFAULT_TLDS = ("com", "net", "org", "co", "jp", "info")
DEFAULT_SUBSTITUTIONS = {
    "a": ("4", "@"),
    "e": ("3",),
    "i": ("1", "l"),
    "l": ("1", "i"),
    "o": ("0",),
    "s": ("5",),
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
    homographs: dict[str, tuple[str, ...]] | None = None
    include_idn: bool = True


def split_domain(domain: str) -> tuple[str, str]:
    labels = domain.strip().lower().rstrip(".").split(".")
    if len(labels) < 2 or not labels[-2] or not labels[-1]:
        raise ValueError(f"Expected a registrable domain like example.com: {domain!r}")
    return ".".join(labels[:-1]), labels[-1]


def to_ascii_domain(domain: str) -> str:
    return domain.encode("idna").decode("ascii")


def generate_variants(seed_domain: str, config: VariantConfig | None = None) -> list[str]:
    config = config or VariantConfig()
    substitutions = config.substitutions or DEFAULT_SUBSTITUTIONS
    homographs = config.homographs or DEFAULT_HOMOGRAPHS
    name, tld = split_domain(seed_domain)
    variants: set[str] = set()

    for index in range(len(name)):
        variants.add(name[:index] + name[index + 1 :] + "." + tld)

    for index in range(len(name) + 1):
        for char in config.insertions:
            variants.add(name[:index] + char + name[index:] + "." + tld)

    for index in range(len(name) - 1):
        if name[index] != name[index + 1]:
            swapped = name[:index] + name[index + 1] + name[index] + name[index + 2 :]
            variants.add(swapped + "." + tld)

    for index, char in enumerate(name):
        for replacement in substitutions.get(char, ()):
            variants.add(name[:index] + replacement + name[index + 1 :] + "." + tld)
        if config.include_idn:
            for replacement in homographs.get(char, ()):
                unicode_domain = name[:index] + replacement + name[index + 1 :] + "." + tld
                variants.add(to_ascii_domain(unicode_domain))

    for keyword in config.keywords:
        variants.add(f"{name}-{keyword}.{tld}")
        variants.add(f"{keyword}-{name}.{tld}")

    for new_tld in config.tlds:
        if new_tld != tld:
            variants.add(f"{name}.{new_tld}")

    variants.discard(seed_domain.strip().lower().rstrip("."))
    return sorted(variants)
