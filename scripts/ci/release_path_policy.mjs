export function isTestReleasePath(filePath) {
  const normalized = filePath.replaceAll("\\", "/").toLowerCase();
  const parts = normalized.split("/");
  const name = parts.at(-1) ?? "";
  return parts.some((part) => ["__tests__", "test", "tests"].includes(part))
    || /^(?:test|spec)[_-]/.test(name)
    || /\.(?:test|spec)\./.test(name);
}
