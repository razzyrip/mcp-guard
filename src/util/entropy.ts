// Shannon entropy calculation for detecting high-entropy strings (possible secrets).

const LOG2 = Math.log(2);

/** Compute Shannon entropy (bits per character) of a string. */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let h = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    h -= p * (Math.log(p) / LOG2);
  }
  return h;
}

/**
 * Returns true if the string looks like it could be a high-entropy secret.
 * Threshold: entropy > 4.5 bits/char AND length >= 20.
 */
export function isHighEntropy(s: string, minLength = 20, threshold = 4.5): boolean {
  return s.length >= minLength && shannonEntropy(s) > threshold;
}
