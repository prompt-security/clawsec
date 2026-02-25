/**
 * Skill Signature Verification Handler for NanoClaw
 *
 * Verifies Ed25519 signatures on skill packages to prevent supply chain attacks.
 * Uses the same pinned public key as advisory feed verification.
 */

import fs from 'fs';
import path from 'path';
import {
  verifyDetachedSignatureWithDetails,
  loadPublicKey,
  sha256File,
  SecurityPolicyError
} from '../lib/signatures.js';

/**
 * Default location of ClawSec's pinned public key (same as advisory feed)
 */
const DEFAULT_PUBLIC_KEY_PATH = path.join(
  __dirname,
  '../advisories/feed-signing-public.pem'
);

/**
 * Verification result interface
 */
export interface VerificationResult {
  valid: boolean;
  signer: string | null;
  packageHash: string;
  verifiedAt: string;
  algorithm: 'Ed25519';
  error?: string;
}

/**
 * Verification parameters interface
 */
export interface VerifyParams {
  packagePath: string;
  signaturePath: string;
  publicKeyPem?: string;      // Optional override of pinned key
  allowUnsigned?: boolean;    // Allow missing signature (default: false)
}

/**
 * Service class for skill package signature verification
 */
export class SkillSignatureVerifier {
  private publicKeyPath: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private logger: any;

  constructor(
    publicKeyPath: string = DEFAULT_PUBLIC_KEY_PATH,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    logger?: any
  ) {
    this.publicKeyPath = publicKeyPath;
    this.logger = logger || console;
  }

  /**
   * Verify Ed25519 signature of a skill package
   */
  async verify(params: VerifyParams): Promise<VerificationResult> {
    const {
      packagePath,
      signaturePath,
      publicKeyPem,
      allowUnsigned = false
    } = params;

    // Validate package file exists
    if (!fs.existsSync(packagePath)) {
      return {
        valid: false,
        signer: null,
        packageHash: '',
        verifiedAt: new Date().toISOString(),
        algorithm: 'Ed25519',
        error: `Package file not found: ${packagePath}`
      };
    }

    // Check signature file exists
    if (!fs.existsSync(signaturePath)) {
      if (allowUnsigned) {
        // Unsigned allowed - compute hash but mark invalid
        const packageHash = sha256File(packagePath);
        return {
          valid: false,
          signer: null,
          packageHash,
          verifiedAt: new Date().toISOString(),
          algorithm: 'Ed25519',
          error: 'No signature file found (unsigned package)'
        };
      } else {
        // Unsigned not allowed - fail
        return {
          valid: false,
          signer: null,
          packageHash: '',
          verifiedAt: new Date().toISOString(),
          algorithm: 'Ed25519',
          error: `Signature file not found: ${signaturePath}`
        };
      }
    }

    // Load public key (either custom or pinned)
    let keyPem: string;
    try {
      if (publicKeyPem) {
        // Custom key provided - validate format
        loadPublicKey(publicKeyPem); // Throws if invalid
        keyPem = publicKeyPem;
      } else {
        // Load pinned ClawSec key
        if (!fs.existsSync(this.publicKeyPath)) {
          return {
            valid: false,
            signer: null,
            packageHash: '',
            verifiedAt: new Date().toISOString(),
            algorithm: 'Ed25519',
            error: `Public key file not found: ${this.publicKeyPath}`
          };
        }
        keyPem = fs.readFileSync(this.publicKeyPath, 'utf8');
        loadPublicKey(keyPem); // Validate pinned key
      }
    } catch (error) {
      if (error instanceof SecurityPolicyError) {
        return {
          valid: false,
          signer: null,
          packageHash: '',
          verifiedAt: new Date().toISOString(),
          algorithm: 'Ed25519',
          error: error.message
        };
      }
      return {
        valid: false,
        signer: null,
        packageHash: '',
        verifiedAt: new Date().toISOString(),
        algorithm: 'Ed25519',
        error: `Failed to load public key: ${error instanceof Error ? error.message : String(error)}`
      };
    }

    // Compute package hash (always, for integrity tracking)
    let packageHash: string;
    try {
      packageHash = sha256File(packagePath);
    } catch (error) {
      return {
        valid: false,
        signer: null,
        packageHash: '',
        verifiedAt: new Date().toISOString(),
        algorithm: 'Ed25519',
        error: `Failed to compute package hash: ${error instanceof Error ? error.message : String(error)}`
      };
    }

    // Verify signature
    const verificationResult = verifyDetachedSignatureWithDetails(
      packagePath,
      signaturePath,
      keyPem
    );

    // Return structured result
    return {
      valid: verificationResult.valid,
      signer: verificationResult.valid ? 'clawsec' : null,
      packageHash,
      verifiedAt: new Date().toISOString(),
      algorithm: 'Ed25519',
      error: verificationResult.error
    };
  }

  /**
   * Get public key fingerprint for auditing
   */
  getPublicKeyFingerprint(): string {
    try {
      const keyPem = fs.readFileSync(this.publicKeyPath, 'utf8');
      const keyObject = loadPublicKey(keyPem);
      const _keyDer = keyObject.export({ type: 'spki', format: 'der' });
      return `sha256:${sha256File(this.publicKeyPath).substring(0, 16)}`;
    } catch (error) {
      this.logger.error({ error }, 'Failed to compute public key fingerprint');
      return 'unknown';
    }
  }
}

/**
 * Error codes for IPC responses
 */
export const ErrorCodes = {
  SIGNATURE_INVALID: 'SIGNATURE_INVALID',
  FILE_NOT_FOUND: 'FILE_NOT_FOUND',
  CRYPTO_ERROR: 'CRYPTO_ERROR',
  SERVICE_UNAVAILABLE: 'SERVICE_UNAVAILABLE'
} as const;

/**
 * Map verification errors to standard error codes
 */
export function mapErrorCode(error: string): string {
  if (error.includes('not found')) {
    return ErrorCodes.FILE_NOT_FOUND;
  }
  if (error.includes('Invalid signature') || error.includes('verification failed')) {
    return ErrorCodes.SIGNATURE_INVALID;
  }
  if (error.includes('public key') || error.includes('PEM')) {
    return ErrorCodes.CRYPTO_ERROR;
  }
  return ErrorCodes.CRYPTO_ERROR;
}
