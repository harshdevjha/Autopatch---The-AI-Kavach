"""
vuln_service_patched.py -- patched version.
Replaces eval() with a whitelist-based safe arithmetic evaluator (ast-based)
that only permits numeric literals and +-*/ -- exactly the "smallest patch
that closes the crack without breaking valid use" principle from the loop,
just for a code-injection bug class instead of a memory bug.
"""
import ast
import operator
import sys

_ALLOWED_OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub,
    ast.Mult: operator.mul, ast.Div: operator.truediv,
    ast.USub: operator.neg,
}

def _safe_eval(node):
    if isinstance(node, ast.Expression):
        return _safe_eval(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _ALLOWED_OPS:
        return _ALLOWED_OPS[type(node.op)](_safe_eval(node.left), _safe_eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _ALLOWED_OPS:
        return _ALLOWED_OPS[type(node.op)](_safe_eval(node.operand))
    raise ValueError("disallowed expression")

def compute(expr: str):
    tree = ast.parse(expr, mode="eval")
    result = _safe_eval(tree)
    print(f"Result: {result}")

if __name__ == "__main__":
    line = sys.stdin.readline().strip()
    try:
        compute(line)
    except Exception as e:
        print(f"Rejected: {e}")
