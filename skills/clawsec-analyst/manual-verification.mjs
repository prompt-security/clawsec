#!/usr/bin/env node

/**
 * Manual Verification Script for ClawSec Analyst Handler
 *
 * This script tests the handler invocation with both dry-run and full event processing.
 *
 * Usage:
 *   ANTHROPIC_API_KEY=<your-key> node skills/clawsec-analyst/manual-verification.mjs
 */

import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs/promises';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ANSI color codes for output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
};

let passCount = 0;
let failCount = 0;

function log(message, color = colors.reset) {
  console.log(`${color}${message}${colors.reset}`);
}

function pass(message) {
  passCount++;
  log(`✓ ${message}`, colors.green);
}

function fail(message) {
  failCount++;
  log(`✗ ${message}`, colors.red);
}

function info(message) {
  log(`ℹ ${message}`, colors.cyan);
}

function section(message) {
  log(`\n${colors.bright}${message}${colors.reset}`, colors.blue);
  log('='.repeat(message.length), colors.blue);
}

/**
 * Run a command and capture output
 */
function runCommand(command, args, env = {}) {
  return new Promise((resolve, reject) => {
    const proc = spawn(command, args, {
      env: { ...process.env, ...env },
      cwd: __dirname,
    });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    proc.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    proc.on('close', (code) => {
      resolve({ code, stdout, stderr });
    });

    proc.on('error', (error) => {
      reject(error);
    });
  });
}

/**
 * Test 1: Verify handler.js exists and is executable
 */
async function testHandlerExists() {
  section('Test 1: Handler File Exists');

  try {
    const handlerPath = path.join(__dirname, 'handler.js');
    await fs.access(handlerPath);
    pass('handler.js exists');
    return true;
  } catch (error) {
    fail(`handler.js not found: ${error.message}`);
    return false;
  }
}

/**
 * Test 2: Test --dry-run without API key (should fail)
 */
async function testDryRunWithoutApiKey() {
  section('Test 2: --dry-run Without API Key (Should Fail)');

  try {
    const result = await runCommand('node', ['handler.js', '--dry-run'], {
      ANTHROPIC_API_KEY: '', // Explicitly unset
    });

    if (result.code !== 0) {
      pass('--dry-run correctly fails without API key');
      if (result.stderr.includes('ANTHROPIC_API_KEY is not set')) {
        pass('Error message mentions ANTHROPIC_API_KEY');
      } else {
        fail('Error message does not mention ANTHROPIC_API_KEY');
      }
      return true;
    } else {
      fail('--dry-run should fail without API key but passed');
      return false;
    }
  } catch (error) {
    fail(`Error running --dry-run test: ${error.message}`);
    return false;
  }
}

/**
 * Test 3: Test --dry-run with API key
 */
async function testDryRunWithApiKey() {
  section('Test 3: --dry-run With API Key');

  const apiKey = process.env.ANTHROPIC_API_KEY;

  if (!apiKey || apiKey.trim() === '' || apiKey === 'test') {
    info('Skipping: ANTHROPIC_API_KEY not set or is test value');
    info('Set a real API key to test this: ANTHROPIC_API_KEY=<your-key> node manual-verification.mjs');
    return true;
  }

  try {
    const result = await runCommand('node', ['handler.js', '--dry-run'], {
      ANTHROPIC_API_KEY: apiKey,
    });

    if (result.code === 0) {
      pass('--dry-run passes with API key set');

      const output = result.stdout + result.stderr;
      if (output.includes('Environment validation passed')) {
        pass('Output contains "Environment validation passed"');
      } else {
        fail('Output missing "Environment validation passed"');
      }

      if (output.includes('API key configured')) {
        pass('Output contains "API key configured"');
      } else {
        fail('Output missing "API key configured"');
      }

      if (output.includes('Ready for operation')) {
        pass('Output contains "Ready for operation"');
      } else {
        fail('Output missing "Ready for operation"');
      }

      return true;
    } else {
      fail('--dry-run failed with API key set');
      log(`stderr: ${result.stderr}`, colors.yellow);
      return false;
    }
  } catch (error) {
    fail(`Error running --dry-run with API key: ${error.message}`);
    return false;
  }
}

/**
 * Test 4: Verify advisory feed exists
 */
async function testAdvisoryFeedExists() {
  section('Test 4: Advisory Feed Exists');

  try {
    const feedPath = path.resolve(__dirname, '../../advisories/feed.json');
    const feedContent = await fs.readFile(feedPath, 'utf-8');
    const feed = JSON.parse(feedContent);

    pass('advisories/feed.json exists and is valid JSON');

    if (feed.advisories && Array.isArray(feed.advisories)) {
      pass(`Found ${feed.advisories.length} advisories in feed`);
    } else {
      fail('feed.json missing advisories array');
    }

    if (feed.version) {
      pass(`Feed version: ${feed.version}`);
    } else {
      fail('feed.json missing version field');
    }

    return true;
  } catch (error) {
    fail(`Error reading advisory feed: ${error.message}`);
    return false;
  }
}

/**
 * Test 5: Verify signature verification setup
 */
async function testSignatureVerification() {
  section('Test 5: Signature Verification Setup');

  try {
    // Check for public key in multiple locations
    const publicKeyPaths = [
      path.resolve(__dirname, '../../clawsec-signing-public.pem'),
      path.resolve(__dirname, '../../advisories/feed-signing-public.pem'),
    ];

    let foundPublicKey = false;
    for (const keyPath of publicKeyPaths) {
      try {
        await fs.access(keyPath);
        pass(`Found public key at ${path.relative(__dirname, keyPath)}`);
        foundPublicKey = true;
        break;
      } catch {
        // Try next path
      }
    }

    if (!foundPublicKey) {
      fail('No public key found in expected locations');
    }

    // Check for signature in feed
    const feedPath = path.resolve(__dirname, '../../advisories/feed.json');
    const feedContent = await fs.readFile(feedPath, 'utf-8');
    const feed = JSON.parse(feedContent);

    if (feed.signature) {
      pass('Feed contains signature field');
    } else {
      info('Feed does not contain signature (may need CLAWSEC_ALLOW_UNSIGNED_FEED=1)');
    }

    return true;
  } catch (error) {
    fail(`Error checking signature verification: ${error.message}`);
    return false;
  }
}

/**
 * Test 6: Verify handler can be imported
 */
async function testHandlerImport() {
  section('Test 6: Handler Module Import');

  try {
    const handlerModule = await import('./handler.js');

    if (handlerModule.default) {
      pass('Handler exports default function');
    } else {
      fail('Handler missing default export');
    }

    if (typeof handlerModule.default === 'function') {
      pass('Handler default export is a function');
    } else {
      fail('Handler default export is not a function');
    }

    return true;
  } catch (error) {
    fail(`Error importing handler: ${error.message}`);
    return false;
  }
}

/**
 * Test 7: Test handler invocation with mock event (requires API key)
 */
async function testHandlerInvocation() {
  section('Test 7: Handler Event Processing');

  const apiKey = process.env.ANTHROPIC_API_KEY;

  if (!apiKey || apiKey.trim() === '' || apiKey === 'test') {
    info('Skipping: ANTHROPIC_API_KEY not set or is test value');
    info('This test requires a real API key to test event processing');
    return true;
  }

  try {
    // Set NODE_ENV to test to suppress warnings
    process.env.NODE_ENV = 'test';

    const handlerModule = await import('./handler.js');
    const handler = handlerModule.default;

    // Create a mock bootstrap event
    const mockEvent = {
      type: 'agent',
      action: 'bootstrap',
      messages: [],
      context: {},
    };

    info('Invoking handler with mock agent:bootstrap event...');

    // Note: This will make a real API call if there are advisories
    // Set CLAWSEC_ALLOW_UNSIGNED_FEED=1 to allow unsigned feed
    process.env.CLAWSEC_ALLOW_UNSIGNED_FEED = '1';

    try {
      await handler(mockEvent);
      pass('Handler invocation completed without errors');

      // Check if messages were added
      if (mockEvent.messages.length > 0) {
        pass(`Handler added ${mockEvent.messages.length} message(s) to event`);
        info(`Message: ${mockEvent.messages[0].content.substring(0, 100)}...`);
      } else {
        info('Handler did not add messages (may indicate no critical advisories)');
      }

      return true;
    } catch (handlerError) {
      // Handler errors should be caught internally, so this is unexpected
      fail(`Handler threw error: ${handlerError.message}`);
      return false;
    }
  } catch (error) {
    fail(`Error testing handler invocation: ${error.message}`);
    return false;
  } finally {
    delete process.env.NODE_ENV;
    delete process.env.CLAWSEC_ALLOW_UNSIGNED_FEED;
  }
}

/**
 * Main test runner
 */
async function main() {
  log(`${colors.bright}ClawSec Analyst - Manual Verification${colors.reset}\n`);

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey || apiKey.trim() === '' || apiKey === 'test') {
    log(`${colors.yellow}⚠ ANTHROPIC_API_KEY not set or is test value${colors.reset}`);
    log(`${colors.yellow}  Some tests will be skipped${colors.reset}`);
    log(`${colors.yellow}  To run all tests: ANTHROPIC_API_KEY=<your-key> node manual-verification.mjs${colors.reset}\n`);
  } else {
    log(`${colors.green}✓ ANTHROPIC_API_KEY is set${colors.reset}\n`);
  }

  // Run all tests
  await testHandlerExists();
  await testDryRunWithoutApiKey();
  await testDryRunWithApiKey();
  await testAdvisoryFeedExists();
  await testSignatureVerification();
  await testHandlerImport();
  await testHandlerInvocation();

  // Report results
  section('Test Results');
  log(`Total: ${passCount + failCount} tests`);
  log(`Passed: ${passCount}`, colors.green);
  log(`Failed: ${failCount}`, colors.red);

  if (failCount === 0) {
    log(`\n${colors.bright}${colors.green}✓ All tests passed!${colors.reset}`);
    process.exit(0);
  } else {
    log(`\n${colors.bright}${colors.red}✗ Some tests failed${colors.reset}`);
    process.exit(1);
  }
}

// Run main
main().catch((error) => {
  console.error(`Fatal error: ${error.message}`);
  console.error(error.stack);
  process.exit(1);
});
