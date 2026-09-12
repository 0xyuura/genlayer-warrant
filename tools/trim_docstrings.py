"""Shorten every docstring in the contract to its first paragraph.

The contract source is sent on chain in full at every deploy. At 31.3 KB the
corrected version never mined, even at twice the network gas price. This first
trim was aimed at a suspected size limit; the real limit turned out to be the
per transaction gas cap, and tools/strip_contract.py records that finding.

The long explanations are not lost: they live in README.md and docs/DESIGN.md,
where a reader looks for them anyway. Behaviour is untouched, and the test suite
is the check on that.
"""
import ast
import io
import sys
import textwrap

MODULE_DOC = (
    'Warrant: a work escrow whose judgement survives adversarial evidence.\n'
    '\n'
    'Prompt injection is a correlated fault: hostile text that steers the\n'
    'leader steers every validator the same way, so consensus alone cannot\n'
    'catch it. The defence is structural. The model returns bits only and never\n'
    'touches money, deterministic checks run before any model call, and\n'
    'agreement is exact equality with no sampling. Everything that votes is a\n'
    'module level function. The full argument is in README.md and\n'
    'docs/DESIGN.md.\n'
)


def first_paragraph(doc: str) -> str:
    cleaned = textwrap.dedent(doc).strip()
    return " ".join(cleaned.split("\n\n")[0].split())


def render(text: str, indent: str) -> list:
    width = 79 - len(indent) - 3
    lines = textwrap.wrap(text, width=width) or [""]
    if len(lines) == 1 and len(indent) + len(lines[0]) + 6 <= 79:
        return [indent + '"""' + lines[0] + '"""\n']
    out = [indent + '"""' + lines[0] + "\n"]
    out += [indent + line + "\n" for line in lines[1:]]
    out.append(indent + '"""\n')
    return out


def main(path: str) -> None:
    src = io.open(path, encoding="utf-8").read()
    lines = src.splitlines(keepends=True)
    tree = ast.parse(src)

    targets = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
            continue
        body = node.body
        if not body or not isinstance(body[0], ast.Expr):
            continue
        value = body[0].value
        if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
            continue
        targets.append((body[0].lineno, body[0].end_lineno, node, value.value))

    for start, end, node, doc in sorted(targets, key=lambda t: -t[0]):
        original = lines[start - 1]
        indent = original[:len(original) - len(original.lstrip())]
        if isinstance(node, ast.Module):
            replacement = ['"""' + MODULE_DOC + '"""\n']
        else:
            replacement = render(first_paragraph(doc), indent)
        lines[start - 1:end] = replacement

    out = "".join(lines)
    io.open(path, "w", encoding="utf-8", newline="\n").write(out)
    print("bytes before:", len(src.encode("utf-8")))
    print("bytes after :", len(out.encode("utf-8")))
    print("docstrings  :", len(targets))


if __name__ == "__main__":
    main(sys.argv[1])
