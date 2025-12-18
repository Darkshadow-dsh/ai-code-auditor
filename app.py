from rules import find_hardcoded_secrets, find_eval_exec_usage
import json

print("Paste AI-generated code. Finish with END")

lines = []
while True:
    line = input()
    if line.strip() == "END":
        break
    lines.append(line)

code = "\n".join(lines)

results = []
results.extend(find_hardcoded_secrets(code))
results.extend(find_eval_exec_usage(code))

output = {
    "total_findings": len(results),
    "findings": results
}

print("\n--- JSON OUTPUT ---")
print(json.dumps(output, indent=2))
