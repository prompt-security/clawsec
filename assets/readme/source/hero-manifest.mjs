import { readFile } from 'node:fs/promises';
import path from 'node:path';

export const COPY_FIELDS = ['eyebrow', 'title', 'tagline', 'supporting'];
export const HERO_SCHEMA_VERSION = 2;

const LOCALE_PATTERN = /^[a-z]{2}(?:-[A-Z]{2})?$/;

const isRecord = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

const validateNonEmptyString = (value, field, failures) => {
  if (typeof value !== 'string' || value.trim().length === 0) {
    failures.push(`${field} must be a non-empty string`);
    return false;
  }
  return true;
};

const validateStringArray = (value, field, failures, { exactLength } = {}) => {
  if (!Array.isArray(value) || value.length === 0) {
    failures.push(`${field} must be a non-empty array of strings`);
    return false;
  }

  if (exactLength !== undefined && value.length !== exactLength) {
    failures.push(`${field} must contain exactly ${exactLength} item${exactLength === 1 ? '' : 's'}`);
  }

  for (const [index, item] of value.entries()) {
    validateNonEmptyString(item, `${field}[${index}]`, failures);
  }
  return true;
};

const validateFiniteNumber = (value, field, failures) => {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    failures.push(`${field} must be a finite number`);
    return false;
  }
  return true;
};

const validateNumberInRange = (value, field, minimum, maximum, failures) => {
  if (!validateFiniteNumber(value, field, failures)) return false;
  if (value < minimum || value > maximum) {
    failures.push(`${field} must be between ${minimum} and ${maximum}`);
    return false;
  }
  return true;
};

const validatePath = (value, field, failures) => {
  if (!validateNonEmptyString(value, field, failures)) return;

  const segments = value.split(/[\\/]/);
  if (path.posix.isAbsolute(value) || path.win32.isAbsolute(value) || segments.includes('..')) {
    failures.push(`${field} must be a repository-relative path without parent traversal`);
  }
};

const validateAccessibility = (value, field, failures) => {
  if (!isRecord(value)) {
    failures.push(`${field} must be an object`);
    return;
  }

  validateNonEmptyString(value.alt, `${field}.alt`, failures);
  validateNonEmptyString(value.title, `${field}.title`, failures);
  validateNonEmptyString(value.description, `${field}.description`, failures);
};

const validateCopy = (copy, field, failures) => {
  if (!isRecord(copy)) {
    failures.push(`${field} must be an object`);
    return;
  }

  validateStringArray(copy.eyebrow, `${field}.eyebrow`, failures, { exactLength: 1 });
  validateStringArray(copy.title, `${field}.title`, failures, { exactLength: 1 });
  validateStringArray(copy.tagline, `${field}.tagline`, failures);
  validateStringArray(copy.supporting, `${field}.supporting`, failures);
};

const validateCoordinateArray = (value, field, expectedLength, failures) => {
  if (!Array.isArray(value)) {
    failures.push(`${field} must be an array of finite numbers`);
    return;
  }

  if (typeof expectedLength === 'number' && value.length !== expectedLength) {
    failures.push(`${field} must contain ${expectedLength} coordinate${expectedLength === 1 ? '' : 's'}`);
  }

  for (const [index, item] of value.entries()) {
    validateNumberInRange(item, `${field}[${index}]`, -50, 460, failures);
    if (index > 0 && typeof item === 'number' && typeof value[index - 1] === 'number' && item <= value[index - 1]) {
      failures.push(`${field} must be strictly increasing`);
      break;
    }
  }
};

const validateLayout = (layout, copy, field, failures) => {
  if (!isRecord(layout)) {
    failures.push(`${field} must be an object`);
    return;
  }

  validateNumberInRange(layout.title_block_y, `${field}.title_block_y`, 0, 460, failures);
  for (const key of ['eyebrow_font_size', 'project_title_font_size', 'tagline_font_size', 'supporting_font_size']) {
    validateNumberInRange(layout[key], `${field}.${key}`, 1, 120, failures);
  }
  validateNumberInRange(layout.eyebrow_letter_spacing, `${field}.eyebrow_letter_spacing`, -10, 20, failures);
  for (const key of ['project_title_y', 'underline_y']) {
    validateNumberInRange(layout[key], `${field}.${key}`, -50, 460, failures);
  }
  if (layout.eyebrow_y !== undefined) {
    validateNumberInRange(layout.eyebrow_y, `${field}.eyebrow_y`, -50, 460, failures);
  }

  validateCoordinateArray(
    layout.tagline_y,
    `${field}.tagline_y`,
    Array.isArray(copy?.tagline) ? copy.tagline.length : undefined,
    failures
  );
  validateCoordinateArray(
    layout.supporting_y,
    `${field}.supporting_y`,
    Array.isArray(copy?.supporting) ? copy.supporting.length : undefined,
    failures
  );

  if (typeof layout.title_block_y === 'number' && Number.isFinite(layout.title_block_y)) {
    const relativeCoordinates = [
      layout.eyebrow_y ?? 0,
      layout.project_title_y,
      layout.underline_y,
      ...(Array.isArray(layout.tagline_y) ? layout.tagline_y : []),
      ...(Array.isArray(layout.supporting_y) ? layout.supporting_y : [])
    ];
    for (const coordinate of relativeCoordinates) {
      if (typeof coordinate === 'number' && Number.isFinite(coordinate)) {
        const absolute = layout.title_block_y + coordinate;
        if (absolute < 0 || absolute > 460) {
          failures.push(`${field} places text or decoration outside the 460px canvas`);
          break;
        }
      }
    }
  }
};

const validateBannerPaths = (entry, field, failures) => {
  if (!isRecord(entry)) {
    failures.push(`${field} must be an object`);
    return false;
  }

  validatePath(entry.readme, `${field}.readme`, failures);
  validatePath(entry.svg, `${field}.svg`, failures);
  validatePath(entry.webp, `${field}.webp`, failures);
  validateAccessibility(entry.accessibility, `${field}.accessibility`, failures);
  return true;
};

const validateExpectedPath = (actual, expected, field, failures) => {
  if (typeof actual === 'string' && actual !== expected) {
    failures.push(`${field} must be ${expected}`);
  }
};

const validateTranslationAssurance = (value, field, failures) => {
  if (!isRecord(value)) {
    failures.push(`${field} must be an object`);
    return;
  }

  validateNonEmptyString(value.label, `${field}.label`, failures);
  validateStringArray(value.accepted_process, `${field}.accepted_process`, failures);
  validateNonEmptyString(value.semantic_basis, `${field}.semantic_basis`, failures);
  if (value.human_native_certified !== false) {
    failures.push(`${field}.human_native_certified must be false`);
  }

  if (!isRecord(value.local_model_challenger)) {
    failures.push(`${field}.local_model_challenger must be an object`);
  } else {
    validateNonEmptyString(value.local_model_challenger.model, `${field}.local_model_challenger.model`, failures);
    validateNonEmptyString(value.local_model_challenger.status, `${field}.local_model_challenger.status`, failures);
    validateNonEmptyString(value.local_model_challenger.reason, `${field}.local_model_challenger.reason`, failures);
  }
};

export const validateHeroManifest = (manifest) => {
  const failures = [];
  if (!isRecord(manifest)) return ['$ must be an object'];

  if (manifest.schema_version !== HERO_SCHEMA_VERSION) {
    failures.push(`$.schema_version must be ${HERO_SCHEMA_VERSION}`);
  }
  validateNonEmptyString(manifest.source_locale, '$.source_locale', failures);
  if (typeof manifest.source_locale === 'string' && !LOCALE_PATTERN.test(manifest.source_locale)) {
    failures.push('$.source_locale must be a supported locale identifier such as en or pt-BR');
  }

  if (!isRecord(manifest.source_copy)) {
    failures.push('$.source_copy must be an object');
  } else {
    for (const field of COPY_FIELDS) {
      validateNonEmptyString(manifest.source_copy[field], `$.source_copy.${field}`, failures);
    }
    if (manifest.source_copy.title !== 'ClawSec') {
      failures.push('$.source_copy.title must preserve the ClawSec project name');
    }
  }

  if (validateBannerPaths(manifest.source_banner, '$.source_banner', failures)) {
    validateExpectedPath(manifest.source_banner.readme, 'README.md', '$.source_banner.readme', failures);
    validateExpectedPath(
      manifest.source_banner.svg,
      'assets/readme/source/hero-layout.svg',
      '$.source_banner.svg',
      failures
    );
    validateExpectedPath(manifest.source_banner.webp, 'assets/readme/hero.webp', '$.source_banner.webp', failures);
  }
  validateTranslationAssurance(manifest.translation_assurance, '$.translation_assurance', failures);

  if (!isRecord(manifest.locales) || Object.keys(manifest.locales).length === 0) {
    failures.push('$.locales must be a non-empty object');
    return failures;
  }

  if (typeof manifest.source_locale === 'string' && manifest.locales[manifest.source_locale] !== undefined) {
    failures.push('$.locales must not include the separately authored source locale');
  }

  for (const [locale, entry] of Object.entries(manifest.locales)) {
    const field = `$.locales.${locale}`;
    if (!LOCALE_PATTERN.test(locale)) {
      failures.push(`${field} uses an invalid locale identifier`);
    }
    if (!validateBannerPaths(entry, field, failures)) continue;

    validateExpectedPath(entry.readme, `README.${locale}.md`, `${field}.readme`, failures);
    validateExpectedPath(
      entry.svg,
      `assets/readme/source/hero-layout-${locale}.svg`,
      `${field}.svg`,
      failures
    );
    validateExpectedPath(entry.webp, `assets/readme/hero-${locale}.webp`, `${field}.webp`, failures);

    validateNonEmptyString(entry.language, `${field}.language`, failures);
    validateCopy(entry.copy, `${field}.copy`, failures);
    if (
      typeof manifest.source_copy?.title === 'string'
      && Array.isArray(entry.copy?.title)
      && entry.copy.title[0] !== manifest.source_copy.title
    ) {
      failures.push(`${field}.copy.title[0] must preserve the ${manifest.source_copy.title} project name`);
    }

    if (!isRecord(entry.back_translation)) {
      failures.push(`${field}.back_translation must be an object`);
    } else {
      for (const copyField of ['eyebrow', 'tagline', 'supporting']) {
        validateNonEmptyString(entry.back_translation[copyField], `${field}.back_translation.${copyField}`, failures);
      }
    }

    validateLayout(entry.layout, entry.copy, `${field}.layout`, failures);
  }

  return failures;
};

export const localeCoverageFailures = (manifestLocales, translatedReadmeLocales) => {
  const manifestSet = new Set(manifestLocales);
  const readmeSet = new Set(translatedReadmeLocales);
  const failures = [];

  for (const locale of [...readmeSet].sort()) {
    if (!manifestSet.has(locale)) failures.push(`README.${locale}.md has no hero manifest entry`);
  }
  for (const locale of [...manifestSet].sort()) {
    if (!readmeSet.has(locale)) failures.push(`hero manifest locale ${locale} has no README.${locale}.md`);
  }
  return failures;
};

export const loadHeroManifest = async (manifestPath) => {
  let source;
  try {
    source = await readFile(manifestPath, 'utf8');
  } catch (error) {
    throw new Error(`Unable to read ${manifestPath}: ${error.message}`);
  }

  let manifest;
  try {
    manifest = JSON.parse(source);
  } catch (error) {
    throw new Error(`Invalid JSON in ${manifestPath}: ${error.message}`);
  }

  const failures = validateHeroManifest(manifest);
  if (failures.length > 0) {
    throw new Error(`Invalid hero manifest:\n${failures.map((failure) => `- ${failure}`).join('\n')}`);
  }
  return manifest;
};
