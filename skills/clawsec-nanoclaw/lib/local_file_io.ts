import fs from 'fs';

export function fileExists(filePath: string): boolean {
  return fs.existsSync(filePath);
}

export function loadBinaryFile(filePath: string): Buffer {
  return fs.readFileSync(filePath);
}

export function loadUtf8File(filePath: string): string {
  return fs.readFileSync(filePath, 'utf8');
}
