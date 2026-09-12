"""Strip comments and function docstrings from the contract, keeping behaviour.

Bradbury enforces a per transaction gas cap of 2**24 = 16,777,216 (EIP-7825).
A deploy carries the whole source as calldata, at roughly 820 gas per byte, so
the 23 KB corrected contract needed about 19.1M gas and was never included, at
any price. Measured on chain: a plain transfer declaring 16,777,216 gas mined
at once, the same transfer declaring 16,777,217 never did, and no deploy above
16.5M gas had landed on Bradbury in the preceding 17 hours.

The explanations are not lost. The annotated source is commit 115442c, and the
argument lives in README.md and docs/DESIGN.md.

Safety check: the abstract syntax tree of the output must equal the tree of the
input with its function and class docstrings removed, or nothing is written.
"""
import ast
import io
import re
import sys
import tokenize

HEADER_PREFIX = '# { "Depends"'


def drop_docstrings(tree: ast.AST) -> ast.AST:
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        body = node.body
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            node.body = body[1:] or [ast.Pass()]
    return tree


def strip(src: str) -> str:
    lines = src.splitlines(keepends=True)

    # Docstrings first, by line range, bottom up so earlier ranges stay valid.
    tree = ast.parse(src)
    ranges = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        first = node.body[0]
        if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)):
            if len(node.body) == 1:
                raise SystemExit("docstring is the only statement in " + node.name)
            ranges.append((first.lineno, first.end_lineno))
    for start, end in sorted(ranges, reverse=True):
        del lines[start - 1:end]

    # Then comments, found by the tokenizer so a hash inside a string is safe.
    src = "".join(lines)
    lines = src.splitlines(keepends=True)
    cuts = {}
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type == tokenize.COMMENT:
            row, col = tok.start
            if tok.string.startswith(HEADER_PREFIX) and row == 1:
                continue
            cuts[row] = col
    out = []
    for i, line in enumerate(lines, start=1):
        if i not in cuts:
            out.append(line)
            continue
        kept = line[:cuts[i]].rstrip()
        if kept:
            out.append(kept + "\n")
    text = "".join(out)
    return re.sub(r"\n{4,}", "\n\n\n", text)


def main(path: str) -> None:
    src = io.open(path, encoding="utf-8").read()
    out = strip(src)
    before = ast.dump(drop_docstrings(ast.parse(src)))
    after = ast.dump(drop_docstrings(ast.parse(out)))
    if before != after:
        raise SystemExit("syntax tree changed, refusing to write")
    io.open(path, "w", encoding="utf-8", newline="\n").write(out)
    print("bytes before:", len(src.encode("utf-8")))
    print("bytes after :", len(out.encode("utf-8")))


if __name__ == "__main__":
    main(sys.argv[1])
