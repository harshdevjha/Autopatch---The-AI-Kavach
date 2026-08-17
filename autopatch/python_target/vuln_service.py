"""
vuln_service.py -- a tiny "config loader" service.
Reads a line from stdin (simulating a request) and evaluates it as a
Python expression to compute a value -- a classic CWE-95 code injection
(the eval() equivalent of the C strcpy overflow: convenient, unbounded,
attacker-controlled).
"""
import sys

def compute(expr: str):
    result = eval(expr)  # VULNERABLE: arbitrary code execution
    print(f"Result: {result}")

if __name__ == "__main__":
    line = sys.stdin.readline().strip()
    compute(line)
