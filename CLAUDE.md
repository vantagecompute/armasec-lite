# armasec-lite

Injectable FastAPI authentication against OIDC providers. A dependency-minimal
reimplementation of [armasec](https://github.com/omnivector-solutions/armasec) 3.x with the
same public API.

Import package `armasec_lite`, distribution `armasec-lite`, Python 3.12+.

Runtime dependencies are exactly three: `fastapi`, `cryptography`, `pydantic`. Adding a
fourth is a design change, not a routine edit. `tests/unit/test_packaging.py` enforces both
the count and the absence of `jose`, `buzz`, `snick`, `auto_name_enum`, `pluggy`, `respx`
and `httpx` by walking the AST of every module.

`armasec_lite/jwt.py` is the only security-critical module. A defect there is an
authentication bypass, not a bug. Read its module docstring before changing it.

## Writing docstrings

**The docstrings in `armasec_lite/` are the API reference.** There is no hand-written
reference page. `@vantagecompute/docusaurus-plugin-pydoc` parses each module with `ast`
at build time and generates the entire reference section from what it finds. A docstring
you skip is a page section that does not exist.

The generator never imports the code, so it sees only what is literally written in the
source: docstrings, signatures, annotations, decorators and class-level assignments.

### What the generator renders, and what that forces

Read `docusaurus/node_modules/@vantagecompute/docusaurus-plugin-pydoc/src/renderer.js` if
you need the detail.
The four consequences that change how you write:

**1. The module docstring becomes the page's `## Overview`, and its FIRST LINE becomes the
Description column of the reference index, truncated to 80 characters.**

Write a first line that is a complete sentence, self-contained, and comfortably under 80
characters so the truncation never bites. It sits in a table beside every sibling module, so
it should distinguish this module from the others at a glance.

```python
# Good: 56 characters, says what the module is
"""A minimal JWS/JWT implementation, replacing python-jose."""

# Bad: truncated mid-word in the index table
"""Exception types and the small assertion helpers armasec uses in place of py-buzz."""

# Bad: burns the budget before saying anything
"""This module provides functionality for handling exceptions."""
```

**2. Module-level constants render bare, as `NAME: annotation = value`, with no
description. `#:` comments above them are NOT captured.**

If a reader needs to understand a constant, explain it in the module docstring prose.
Nowhere else will reach the page. `JWKS_REFRESH_INTERVAL`, `MAX_BODY_BYTES`,
`DEFAULT_TIMEOUT`, `MAX_REDIRECTS` and `SUPPORTED_ALGORITHMS` all need this. Keep the `#:`
comments anyway; they serve someone reading the source.

**3. Class attributes render as a table with columns Attribute, Type and Default, and no
description column.**

The class docstring's `Attributes:` section is the only place a reader learns what a field
means. Every class with public attributes needs one, and it must cover every attribute.

**4. `__init__` and `__call__` are always rendered. Everything else beginning with an
underscore is private and never rendered.**

An earlier version of this file said these two render only when they carry a docstring.
That is wrong, and the difference matters: an undocumented `__init__` produces an **empty
section** on the page rather than being omitted. So a missing docstring there is visible to
readers as a gap, not hidden.

`TokenSecurity.__call__` is the most important method in the library. Methods like it earn
a substantial docstring, not a one-liner.

**5. Use `###` and below for any heading inside a docstring, never `##`.**

The generator emits docstrings verbatim into the page beneath its own `## Overview`
heading. An `##` in your prose escapes that section and collides with the generator's own
`## Constants` and `## Classes` headings, producing duplicate anchors and a broken table of
contents. This was a real defect found by building the site and reading the output.

### Module docstrings

Two to five short paragraphs. Cover: what this module is for, where it sits in the request
path, its constants, and anything non-obvious a reader would otherwise have to reconstruct
from the source.

Non-obvious is the operative word. Prefer the thing that is surprising, deliberate, or
load-bearing over a restatement of the module's name:

- `http.py`: `urllib.request.build_opener()` installs `FileHandler`, so an opener will
  happily read `file://` URLs. The scheme guard in `get_json` is therefore load-bearing and
  not redundant with the URL validation in `schemas.py`.
- `openid_config_loader.py`: the lock is a `threading.Lock` and not an `asyncio.Lock`
  because an `asyncio.Lock` binds to the loop that first awaits it and goes stale across
  test loops.
- `schemas.py`: `OpenidConfig.issuer` is a plain `str` and deliberately not `AnyHttpUrl`,
  because it is compared against a token's `iss` claim by exact string equality and
  normalization would reject valid tokens from providers publishing a bare-host issuer.
- `exceptions.py`: `handle_errors` deliberately does not re-wrap `ArmasecError` subclasses,
  unlike py-buzz, so a specific 401 is not flattened into a generic 500.

If you find yourself writing a comment in the source that explains why something is the way
it is, ask whether it belongs in the module docstring instead, where readers of the
reference will see it.

### Class and function docstrings

Google style, which is what the codebase already uses.

Every public function and method needs `Args:` covering every parameter. Add `Returns:`
when the return value is not obvious from the name and annotation.

**`Raises:` matters more here than in most projects.** This is an authentication library:
the exception type a call raises determines the HTTP status a client sees. A caller needs to
know that `TokenDecoder.decode` can raise `ExpiredSignatureError` (401) or
`PayloadMappingError` (500), and what the difference means. Document it.

```python
def decode(self, token: str, **claims: Any) -> TokenPayload:
    """
    Decode a JWT into a TokenPayload, checking signatures and claims.

    Args:
        token:  The token to decode.
        claims: Additional constraints, such as `audience` or `issuer`. May include an
                `options` dict merged over `decode_options_override`.

    Returns:
        The verified payload, with `original_token` set to the input token.

    Raises:
        AuthenticationError: The token is malformed, its signature does not verify, or a
            claim check failed. Subclasses carry the specific reason and all map to 401.
        PayloadMappingError: The configured `permission_extractor` did not match a path in
            the decoded token. Maps to 500, because that is a server misconfiguration
            rather than a bad request.
    """
```

### Style

Explain why, not what. The signature already says what. A docstring reading
"Initializes the TokenSecurity instance" is worse than no docstring, because it occupies the
space where the useful sentence would go.

Say when something is deliberate. Several choices in this codebase look wrong until you know
the reason, and a reader who does not know will "fix" them.

Do not pad to fill a template. If a function has no failure modes, omit `Raises:`.

**Never use the em-dash (U+2014) or en-dash (U+2013) character.** Use commas, colons,
parentheses, or separate sentences. Hyphens in compound words are fine. This applies to
every file in the repository, not only docstrings.

### Adding a new module

The plugin's module list in `docusaurus/docusaurus.config.ts` is explicit. A new module
under `armasec_lite/` generates no reference page until you add it there, with a label.

`.github/workflows/deploy-docs.yml` fails the docs build when the number of generated pages
does not match the number of declared modules, so a module that is declared but fails to
introspect breaks the build rather than silently vanishing. It derives both counts
dynamically, so it needs no update when you add a module.

Do not add `armasec_lite/__init__.py`: it is re-exports, and its page would duplicate the
others.

### Checking your work

```bash
# Every module's first docstring line, with its length. Keep them under 80.
for f in armasec_lite/*.py armasec_lite/pluggable/*.py; do
  python3 -c "
import ast
d = ast.get_docstring(ast.parse(open('$f').read()))
line = (d or '').strip().split(chr(10))[0] if d else '<NO MODULE DOCSTRING>'
print(f'{len(line):3d}  $f  {line}')
"
done

# Generate and read the reference. It is the actual deliverable, and building it is the
# only way to catch heading collisions and layout problems.
cd docusaurus && npm ci && npm run build && ls docs/api-reference/
```

**Read the built output, do not just check that the build passed.** Two defects in this
repository's docs were found only by reading generated pages: three module descriptions
silently truncated in the index table, and `##` headings in docstrings colliding with the
generator's own section headings.

### Renderer notes

`Args:`, `Returns:` and `Raises:` blocks render as single run-on paragraphs, because the
renderer emits docstring bodies verbatim into Markdown and Markdown collapses the newlines.
The content is correct; the formatting is poor, and it is worst on long `Raises:` sections.

This was fixed upstream in `@vantagecompute/docusaurus-plugin-pydoc` v0.1.1, which this
project depends on. Recognized Google-style sections now render as Markdown lists.

The general rule still holds: do not work around a rendering problem by reformatting
docstrings into Markdown. They would then read badly in an editor, in `help()`, and in every
IDE tooltip, which is where most people actually meet them. Fix the renderer in
`vantagecompute/docusaurus-plugin-pydoc` instead, which improves every Vantage project using
the plugin.

## Testing

`just test` runs the unit suite. `just lint` runs `ruff check`, `ruff format --check` and
`mypy` in strict mode. Both must pass before a commit.

Test-driven: write the failing test, run it, watch it fail for the reason you expect, then
implement. For a security defense, go further and confirm the test fails when the defense is
removed. A passing test proves nothing if it would also pass against undefended code, and
that has already happened once in this codebase: the algorithm-confusion test passed for the
wrong reason until someone checked, because the fixture it used happened to lack the field
that would have made the forgery succeed.

`tests/unit/test_jwt_attacks.py` is the attack suite. Its test names are consumed by a
benchmark that publishes a security-posture chart, so a name there is a public claim about
what is defended. Do not rename one casually, and do not let a name outlive what its test
actually checks.

## The justfile

`justfile` is a verbatim copy of `vantage-mcp-infra`'s, kept deliberately so it can be
pruned by hand later. Most of its recipes reference infrastructure this repository does not
have. `test`, `test-cov`, `lint`, `fmt` and the `docs-*` recipes work. Leave the rest alone.
