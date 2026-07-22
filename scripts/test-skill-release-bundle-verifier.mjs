import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const python = process.env.PYTHON_BIN || 'python3';
const openssl = process.env.OPENSSL_BIN || 'openssl';
const testPath = fileURLToPath(new URL('./ci/test_verify_skill_release_bundle.py', import.meta.url));

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    ...options,
  });

  assert.ifError(result.error);
  return result;
}

const pythonVersion = run(python, ['--version']);
assert.equal(
  pythonVersion.status,
  0,
  `Python is required for release-bundle verifier tests:\n${pythonVersion.stderr}`,
);

const opensslVersion = run(openssl, ['version']);
assert.equal(
  opensslVersion.status,
  0,
  `OpenSSL 3 is required for release-bundle verifier tests:\n${opensslVersion.stderr}`,
);
assert.match(
  opensslVersion.stdout.trim(),
  /^OpenSSL 3(?:\.|\s)/,
  `OpenSSL 3 is required for release-bundle verifier tests; got: ${opensslVersion.stdout.trim()}`,
);

const tests = run(python, [testPath], {
  env: {
    ...process.env,
    OPENSSL_BIN: openssl,
    PYTHONPYCACHEPREFIX: process.env.PYTHONPYCACHEPREFIX || '/tmp/clawsec-python-cache',
  },
  stdio: 'inherit',
});

assert.equal(tests.status, 0, 'Release-bundle verifier regression tests failed');
