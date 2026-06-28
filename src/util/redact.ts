// Utilities for redacting sensitive values from objects/strings.
// Never log the actual secret — only the pattern name + field path.

/** Replace a value in a nested object at a dot-separated path. */
export function redactPath(
  obj: Record<string, unknown>,
  path: string,
  replacement = "***REDACTED***",
): Record<string, unknown> {
  const parts = path.split(".");
  const result = deepClone(obj);
  let cursor: Record<string, unknown> = result;
  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i];
    if (typeof cursor[part] === "object" && cursor[part] !== null) {
      cursor = cursor[part] as Record<string, unknown>;
    } else {
      return result; // path doesn't exist, no-op
    }
  }
  const last = parts[parts.length - 1];
  if (last in cursor) {
    cursor[last] = replacement;
  }
  return result;
}

/** Replace all occurrences of a literal string in a string value. */
export function redactString(value: string, secret: string, replacement = "***REDACTED***"): string {
  return value.split(secret).join(replacement);
}

/** Deep clone a plain object (no functions, no class instances). */
export function deepClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}
