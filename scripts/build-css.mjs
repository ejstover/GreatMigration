// One-shot native compilation avoids the CLI's unused file-watcher dependency chain.
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile, optimize } from '@tailwindcss/node';
import { Scanner } from '@tailwindcss/oxide';

const root = fileURLToPath(new URL('../', import.meta.url));
const input = path.join(root, 'static', 'tailwind.css');
const compiler = await compile(await readFile(input, 'utf8'), {
  base: path.dirname(input),
  onDependency() {},
});
const scanner = new Scanner({ sources: compiler.sources });
const result = optimize(compiler.build(scanner.scan()), { minify: true, file: input });
await writeFile(path.join(root, 'static', 'app.css'), result.code + '\n', 'utf8');
console.log('Built static/app.css');
