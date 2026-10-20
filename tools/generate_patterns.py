#!/usr/bin/env python3

import sys
from collections import deque
from pathlib import Path


PATTERNS = {
    "sql": (
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "UNION",
        "DROP",
        "CONCAT",
        "PRAGMA",
        "1=1",
        "SLEEP",
    ),
    "shell": (
        "nc",
        "netcat",
        "bash",
        "busybox",
        "&",
        "sh",
        "dev",
        "tcp",
        "mkfifo",
        "tmp",
        "/",
        "socket",
    ),
}


def build_automaton(patterns):
    edges = [{}]
    outputs = [[]]
    lengths = []
    first_bytes = set()

    for pattern in patterns:
        pattern = pattern.lower().encode("ascii")
        first_bytes.add(pattern[0])
        state = 0
        for byte in pattern:
            if byte not in edges[state]:
                edges[state][byte] = len(edges)
                edges.append({})
                outputs.append([])
            state = edges[state][byte]
        outputs[state].append(len(pattern))
        lengths.append(len(pattern))

    failures = [0] * len(edges)
    transitions = [[0] * 256 for _ in edges]
    queue = deque()
    for byte, state in edges[0].items():
        transitions[0][byte] = state
        queue.append(state)

    while queue:
        state = queue.popleft()
        failure = failures[state]
        for byte in range(256):
            child = edges[state].get(byte)
            if child is None:
                transitions[state][byte] = transitions[failure][byte]
                continue
            transitions[state][byte] = child
            failures[child] = transitions[failure][byte]
            outputs[child].extend(outputs[failures[child]])
            queue.append(child)

    offsets = []
    counts = []
    flat_outputs = []
    for state_outputs in outputs:
        offsets.append(len(flat_outputs))
        counts.append(len(state_outputs))
        flat_outputs.extend(state_outputs)

    return (
        transitions,
        offsets,
        counts,
        flat_outputs,
        sorted(first_bytes),
    )


def emit_array(name, ctype, values, width=16):
    lines = [f"static const {ctype} {name}[] = {{"]
    for start in range(0, len(values), width):
        row = ", ".join(str(value) for value in values[start : start + width])
        lines.append(f"    {row},")
    lines.append("};")
    return "\n".join(lines)


def main(output_path):
    lines = [
        "#ifndef SANITIZEC_PATTERNS_GENERATED_H",
        "#define SANITIZEC_PATTERNS_GENERATED_H",
        "",
        '#include "sanitizec_pattern.h"',
        "",
    ]

    for name, patterns in PATTERNS.items():
        transitions, offsets, counts, outputs, starts = build_automaton(patterns)
        state_count = len(offsets)
        lines.extend(
            (
                emit_array(f"{name}_transitions", "uint16_t",
                           [value for row in transitions for value in row]),
                emit_array(f"{name}_output_offsets", "uint16_t", offsets),
                emit_array(f"{name}_output_counts", "uint8_t", counts),
                emit_array(f"{name}_output_lengths", "uint8_t", outputs),
                emit_array(f"{name}_first_bytes", "uint8_t", starts),
                f"const sanitizec_pattern_automaton_t sanitizec_{name}_automaton = {{",
                f"    {name}_transitions,",
                f"    {name}_output_offsets,",
                f"    {name}_output_counts,",
                f"    {name}_output_lengths,",
                f"    {name}_first_bytes,",
                f"    {state_count},",
                f"    {len(starts)},",
                "};",
                "",
            )
        )

    lines.extend(("#endif", ""))
    Path(output_path).write_text("\n".join(lines), encoding="ascii")


if __name__ == "__main__":
    main(sys.argv[1])
