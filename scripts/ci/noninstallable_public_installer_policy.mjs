import { TextDecoder } from "node:util";

const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });
const CONTROL_OR_FORMAT = /[\p{Cc}\p{Cf}]/u;
const DEFAULT_IGNORABLE = /\p{Default_Ignorable_Code_Point}/u;
const WHITE_SPACE = /\p{White_Space}/u;
const EXPANSION_MARKER = "\uE000";
const CORE_ENTITIES = new Map([
  ["amp", "&"],
  ["apos", "'"],
  ["gt", ">"],
  ["lt", "<"],
  ["nbsp", "\u00a0"],
  ["quot", '"'],
]);

function flagDecodedSyntaxDelimiter(decoded, encoding, issues) {
  if (/[\s'"`<>]/u.test(decoded)) {
    issues.add(
      `${encoding}-encoded syntax delimiter is not allowed in non-installable documentation`,
    );
  }
}

function decodeMarkdown(input, issues) {
  if (typeof input === "string") {
    return input;
  }
  try {
    return UTF8_DECODER.decode(input);
  } catch {
    issues.add("documentation is not valid UTF-8");
    return null;
  }
}

function decodeEntityPass(value, issues) {
  const numericDecoded = value.replace(
    /&#(?:x([0-9a-f]+)|([0-9]+));/gi,
    (entity, hexadecimal, decimal) => {
      const codePoint = Number.parseInt(hexadecimal || decimal, hexadecimal ? 16 : 10);
      if (
        !Number.isSafeInteger(codePoint) ||
        codePoint > 0x10ffff ||
        (codePoint >= 0xd800 && codePoint <= 0xdfff)
      ) {
        issues.add(`invalid numeric HTML entity: ${entity}`);
        return entity;
      }
      const decoded = String.fromCodePoint(codePoint);
      flagDecodedSyntaxDelimiter(decoded, "HTML", issues);
      return decoded;
    },
  );
  return numericDecoded.replace(/&([a-z][a-z0-9]+);/gi, (entity, name) => {
    const decoded = CORE_ENTITIES.get(name.toLowerCase());
    if (decoded === undefined) {
      return entity;
    }
    flagDecodedSyntaxDelimiter(decoded, "HTML", issues);
    return decoded;
  });
}

function decodePercentPass(value, issues) {
  return value.replace(/(?:%[0-9a-f]{2})+/gi, (encoded) => {
    try {
      const decoded = decodeURIComponent(encoded);
      flagDecodedSyntaxDelimiter(decoded, "percent", issues);
      return decoded;
    } catch {
      issues.add(`invalid percent-encoded UTF-8 sequence: ${encoded}`);
      return encoded;
    }
  });
}

function decodeEntities(value, issues) {
  let decoded = value;
  for (let pass = 0; pass < 8; pass += 1) {
    const next = decodeEntityPass(decodePercentPass(decoded, issues), issues);
    if (next === decoded) {
      break;
    }
    decoded = next;
  }
  if (/&#/.test(decoded)) {
    issues.add("malformed or excessively nested numeric HTML entity");
  }
  if (/&[a-z][a-z0-9]+;/i.test(decoded)) {
    issues.add("unsupported or excessively nested named HTML entity");
  }
  return decoded;
}

function validateCharacters(value, issues) {
  for (const character of value) {
    if (character === "\n" || character === " ") {
      continue;
    }
    if (CONTROL_OR_FORMAT.test(character)) {
      issues.add("control, zero-width, or bidirectional formatting character is not allowed");
      return;
    }
    if (DEFAULT_IGNORABLE.test(character)) {
      issues.add("default-ignorable, zero-width, or variation character is not allowed");
      return;
    }
    if (WHITE_SPACE.test(character)) {
      issues.add("non-ASCII whitespace is not allowed");
      return;
    }
    const compatibilityNormalized = character.normalize("NFKC");
    if (
      compatibilityNormalized !== character &&
      /[\s'"`<>]/u.test(compatibilityNormalized)
    ) {
      issues.add("Unicode compatibility character normalizes to a syntax delimiter");
      return;
    }
  }
}

function findMarkupEnd(value, start) {
  let quote = "";
  for (let index = start + 1; index < value.length; index += 1) {
    const character = value[index];
    if (quote) {
      if (character === quote) {
        quote = "";
      }
    } else if (character === '"' || character === "'") {
      quote = character;
    } else if (character === ">") {
      return index;
    }
  }
  return -1;
}

function shellProtectedLessThanPositions(value) {
  const protectedPositions = new Set();
  let quote = "";
  let token = "";

  const tokenContainsUrl = () =>
    /[a-z][a-z0-9+.-]*:\/\/[^\s]*$/i.test(token);
  const appendTokenCharacter = (character) => {
    token += /\s/u.test(character) ? "_" : character;
  };

  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (character === "\n") {
      quote = "";
      token = "";
      continue;
    }
    if (quote) {
      if (character === quote) {
        quote = "";
      } else if (character === "<") {
        if (tokenContainsUrl()) {
          protectedPositions.add(index);
        }
        token += character;
      } else if (
        quote === '"' &&
        character === "\\" &&
        index + 1 < value.length
      ) {
        if (value[index + 1] === "<") {
          if (tokenContainsUrl()) {
            protectedPositions.add(index + 1);
          }
        }
        appendTokenCharacter(value[index + 1]);
        index += 1;
      } else {
        appendTokenCharacter(character);
      }
      continue;
    }

    if (character === "'" || character === '"') {
      quote = character;
    } else if (character === "\\" && index + 1 < value.length) {
      if (value[index + 1] === "<") {
        if (tokenContainsUrl()) {
          protectedPositions.add(index + 1);
        }
      }
      appendTokenCharacter(value[index + 1]);
      index += 1;
    } else if (/\s/u.test(character) || /[;&|()]/.test(character)) {
      token = "";
    } else {
      token += character;
    }
  }

  return protectedPositions;
}

function markupViews(value, issues) {
  let removed = "";
  let spaced = "";
  let index = 0;
  const protectedLessThan = shellProtectedLessThanPositions(value);

  while (index < value.length) {
    if (value.startsWith("<!--", index)) {
      const end = value.indexOf("-->", index + 4);
      if (end === -1) {
        issues.add("unterminated HTML comment is not allowed");
        break;
      }
      spaced += " ";
      index = end + 3;
      continue;
    }

    const tagStart =
      value[index] === "<" &&
      !protectedLessThan.has(index) &&
      /[A-Za-z/!?]/.test(value[index + 1] || "");
    if (tagStart) {
      const end = findMarkupEnd(value, index);
      if (end === -1) {
        issues.add("unterminated HTML tag is not allowed");
        break;
      }
      spaced += " ";
      index = end + 1;
      continue;
    }

    removed += value[index];
    spaced += value[index];
    index += 1;
  }

  return [removed, spaced];
}

function findBalancedEnd(value, start, open, close) {
  let depth = 0;
  let quote = "";
  for (let index = start; index < value.length; index += 1) {
    const character = value[index];
    if (character === "\\") {
      index += 1;
      continue;
    }
    if (quote) {
      if (character === quote) {
        quote = "";
      }
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
    } else if (character === open) {
      depth += 1;
    } else if (character === close) {
      depth -= 1;
      if (depth === 0) {
        return index;
      }
    }
  }
  return -1;
}

function validateMarkdownLinkPolicy(value, issues) {
  const inlineOrReferenceLink = /\][ \t\n]*(?:\(|\[)/;
  const withoutPlainIpv6Urls = value.replace(
    /\b[a-z][a-z0-9+.-]{1,31}:\/\/(?:[^/\s@]+@)?\[[^\]\s/]+\]:[0-9]+/gi,
    "",
  );
  const referenceDefinition = withoutPlainIpv6Urls.includes("]:");
  const automaticLink = /<(?:[a-z][a-z0-9+.-]{1,31}:[^<>\s]*|[^<>\s@]+@[^<>\s@]+)>/i;
  const htmlLinkOrImage = /<\s*\/?\s*(?:a|image|img)\b/i;
  if (
    inlineOrReferenceLink.test(value) ||
    referenceDefinition ||
    automaticLink.test(value) ||
    htmlLinkOrImage.test(value)
  ) {
    issues.add(
      "Markdown links and images are not allowed in non-installable documentation; use plain URLs",
    );
  }
}

function validateShellSyntaxPolicy(value, issues) {
  if (value.includes("$(")) {
    issues.add("shell command substitution is not allowed in non-installable documentation");
  }
}

function flagNonFenceBackticks(value, issues) {
  if (value.includes("`")) {
    issues.add(
      "non-fence backticks are not allowed in non-installable documentation; use fenced code blocks",
    );
  }
}

function projectMarkdownFences(value, issues) {
  const projected = [];
  let fenceCharacter = "";
  let fenceWidth = 0;

  for (const line of value.split("\n")) {
    if (!fenceCharacter) {
      const opening = line.match(/^( {0,3})(`{3,}|~{3,})(.*)$/);
      if (opening) {
        const delimiter = opening[2];
        const infoString = opening[3];
        if (delimiter[0] === "`" && infoString.includes("`")) {
          flagNonFenceBackticks(line, issues);
          projected.push(line);
          continue;
        }
        flagNonFenceBackticks(infoString, issues);
        fenceCharacter = delimiter[0];
        fenceWidth = delimiter.length;
        projected.push(`${opening[1]}${infoString}`);
        continue;
      }
      flagNonFenceBackticks(line, issues);
      projected.push(line);
      continue;
    }

    const closing = line.match(/^ {0,3}(`{3,}|~{3,})[ \t]*$/);
    if (
      closing &&
      closing[1][0] === fenceCharacter &&
      closing[1].length >= fenceWidth
    ) {
      fenceCharacter = "";
      fenceWidth = 0;
      projected.push("");
      continue;
    }
    flagNonFenceBackticks(line, issues);
    projected.push(line);
  }

  return projected.join("\n");
}

function decodeAsciiEscapes(value) {
  return value
    .replace(/\\x([0-9a-f]{2})/gi, (_escape, hexadecimal) =>
      String.fromCodePoint(Number.parseInt(hexadecimal, 16)))
    .replace(
      /\\u(?:\{([0-9A-Fa-f]{1,6})\}|([0-9A-Fa-f]{4}))/g,
      (escape, braced, fixed) => {
        const codePoint = Number.parseInt(braced || fixed, 16);
        return codePoint <= 0x10ffff && !(codePoint >= 0xd800 && codePoint <= 0xdfff)
          ? String.fromCodePoint(codePoint)
          : escape;
      },
    );
}

const ANSI_SIMPLE_ESCAPES = new Map([
  ["a", "\u0007"],
  ["b", "\b"],
  ["e", "\u001b"],
  ["E", "\u001b"],
  ["f", "\f"],
  ["n", "\n"],
  ["r", "\r"],
  ["t", "\t"],
  ["v", "\v"],
  ["\\", "\\"],
  ["'", "'"],
  ['"', '"'],
  ["?", "?"],
]);

function ansiCodePoint(match, radix) {
  const codePoint = Number.parseInt(match, radix);
  return (
    codePoint <= 0x10ffff &&
    !(codePoint >= 0xd800 && codePoint <= 0xdfff)
  )
    ? String.fromCodePoint(codePoint)
    : null;
}

function decodeAnsiCString(value) {
  let output = "";

  for (let index = 0; index < value.length; index += 1) {
    if (value[index] !== "\\" || index + 1 >= value.length) {
      output += value[index];
      continue;
    }

    const remaining = value.slice(index + 1);
    const simple = ANSI_SIMPLE_ESCAPES.get(remaining[0]);
    if (simple !== undefined) {
      output += simple;
      index += 1;
      continue;
    }

    const control = remaining.match(/^c(.)/s);
    if (control) {
      output += String.fromCodePoint(control[1].toUpperCase().codePointAt(0) & 0x1f);
      index += control[0].length;
      continue;
    }

    const hexadecimal = remaining.match(/^x([0-9a-f]{1,2})/i);
    if (hexadecimal) {
      output += ansiCodePoint(hexadecimal[1], 16);
      index += hexadecimal[0].length;
      continue;
    }

    const unicode = remaining.match(/^u([0-9A-Fa-f]{1,4})/);
    if (unicode) {
      output += ansiCodePoint(unicode[1], 16) ?? `\\${unicode[0]}`;
      index += unicode[0].length;
      continue;
    }

    const longUnicode = remaining.match(/^U([0-9A-Fa-f]{1,8})/);
    if (longUnicode) {
      output += ansiCodePoint(longUnicode[1], 16) ?? `\\${longUnicode[0]}`;
      index += longUnicode[0].length;
      continue;
    }

    const octal = remaining.match(/^([0-7]{1,3})/);
    if (octal) {
      output += ansiCodePoint(octal[1], 8);
      index += octal[0].length;
      continue;
    }

    output += `\\${remaining[0]}`;
    index += 1;
  }

  return output;
}

function joinLiteralObfuscators(value) {
  return decodeAsciiEscapes(value)
    .replaceAll("\\", "")
    .replace(/['"`*~]/g, "");
}

function shellQuotedTokenView(value) {
  let output = "";
  let quote = "";

  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (!quote) {
      if (character === "\\" && index + 1 < value.length) {
        const escaped = value[index + 1];
        if (escaped !== "\n") {
          output += /[\s'"`<>]/u.test(escaped) ? "_" : escaped;
        }
        index += 1;
      } else if (character === "'" || character === '"') {
        quote = character;
      } else {
        output += character;
      }
      continue;
    }

    if (character === quote) {
      quote = "";
      continue;
    }
    if (quote === '"' && character === "\\" && index + 1 < value.length) {
      const escaped = value[index + 1];
      if (['$', "`", '"', "\\", "\n"].includes(escaped)) {
        output += /[\s'"`<>]/u.test(escaped) ? "_" : escaped;
        index += 1;
        continue;
      }
    }
    output += /[\s'"`<>]/u.test(character) ? "_" : character;
  }

  return output;
}

function findQuotedEnd(value, start, quote) {
  for (let index = start + 1; index < value.length; index += 1) {
    if (value[index] === "\n") {
      return -1;
    }
    if (value[index] === "\\") {
      index += 1;
    } else if (value[index] === quote) {
      return index;
    }
  }
  return -1;
}

function shellExpansionSpans(value) {
  const spans = [];
  for (let index = 0; index < value.length; index += 1) {
    let end = -1;
    if (value[index] === "`") {
      end = findQuotedEnd(value, index, "`");
    } else if (value[index] === "$" && ["'", '"'].includes(value[index + 1])) {
      end = findQuotedEnd(value, index + 1, value[index + 1]);
    } else if (value.startsWith("${", index)) {
      end = findBalancedEnd(value, index + 1, "{", "}");
    } else if (value.startsWith("$(", index)) {
      end = findBalancedEnd(value, index + 1, "(", ")");
    } else if (value[index] === "$") {
      const variable = value.slice(index).match(/^\$(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!-])/);
      if (variable) {
        end = index + variable[0].length - 1;
      }
    }
    if (end > index) {
      spans.push({ start: index, end });
      index = end;
    }
  }
  return spans;
}

function replaceSpans(value, spans, replacement) {
  let output = "";
  let cursor = 0;
  for (const span of spans) {
    output += value.slice(cursor, span.start);
    output += replacement;
    cursor = span.end + 1;
  }
  return output + value.slice(cursor);
}

function staticallyKnownExpansion(expansion) {
  if (expansion.startsWith("$'")) {
    return {
      canBeUnknown: false,
      conditional: false,
      value: decodeAnsiCString(expansion.slice(2, -1)),
    };
  }
  if (expansion.startsWith('$"')) {
    return {
      canBeUnknown: false,
      conditional: false,
      value: expansion.slice(2, -1),
    };
  }
  if (!expansion.startsWith("${")) {
    return null;
  }
  const body = expansion.slice(2, -1);
  const parameterDefault = body.match(
    /^(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!_-])(?::?([-+=]))([\s\S]*)$/,
  );
  if (!parameterDefault) {
    return null;
  }
  return {
    canBeUnknown: parameterDefault[1] !== "+",
    conditional: true,
    value: parameterDefault[2],
  };
}

function staticallyKnownExpansionViews(value, spans, issues) {
  const descriptors = spans.map((span) =>
    staticallyKnownExpansion(value.slice(span.start, span.end + 1)));
  const conditionalCount = descriptors.filter(
    (descriptor) => descriptor?.conditional,
  ).length;
  const hasKnownExpansion = descriptors.some(Boolean);
  if (!hasKnownExpansion) {
    return [];
  }

  const render = (mask) => {
    let output = "";
    let cursor = 0;
    let conditionalIndex = 0;
    for (let index = 0; index < spans.length; index += 1) {
      const span = spans[index];
      const descriptor = descriptors[index];
      output += value.slice(cursor, span.start);
      if (!descriptor) {
        output += value.slice(span.start, span.end + 1);
      } else if (!descriptor.conditional) {
        output += descriptor.value;
      } else {
        output += (mask & (1 << conditionalIndex)) === 0
          ? (
            descriptor.canBeUnknown
              ? value.slice(span.start, span.end + 1)
              : ""
          )
          : descriptor.value;
        conditionalIndex += 1;
      }
      cursor = span.end + 1;
    }
    return output + value.slice(cursor);
  };

  if (conditionalCount > 4) {
    issues.add("too many interacting statically known shell expansions");
    const allKnownMask = (2 ** conditionalCount) - 1;
    return [render(0), render(allKnownMask)];
  }

  const views = [];
  for (let mask = 0; mask < 2 ** conditionalCount; mask += 1) {
    views.push(render(mask));
  }
  return views;
}

function isSubsequence(candidate, value) {
  let candidateIndex = 0;
  for (const character of value) {
    if (character === candidate[candidateIndex]) {
      candidateIndex += 1;
    }
  }
  return candidateIndex === candidate.length;
}

function minimumAuthorityEvidence(authority) {
  return Math.max(2, authority.length - 2);
}

function flagAmbiguousAuthorityFragments(value, spans, issues) {
  if (spans.length === 0) {
    return;
  }
  const marked = joinLiteralObfuscators(replaceSpans(value, spans, EXPANSION_MARKER))
    .normalize("NFKC")
    .toLowerCase();
  for (const candidate of marked.match(/[a-z_\uE000]+/g) || []) {
    if (!candidate.includes(EXPANSION_MARKER)) {
      continue;
    }
    const skeleton = candidate.replaceAll(EXPANSION_MARKER, "");
    for (const authority of ["skills", "clawhub", "install_skill"]) {
      if (
        skeleton.length >= minimumAuthorityEvidence(authority) &&
        isSubsequence(skeleton, authority)
      ) {
        issues.add("ambiguous public installer authority fragmentation");
      }
    }
  }
}

function normalizedAuthorityText(value) {
  return value
    .normalize("NFKC")
    .toLowerCase()
    .replace(
      /\b(skills|clawhub)(?:-v?[0-9][a-z0-9._+-]*)?(?:[^a-z0-9_\s'"`<>\uE000-][^\s'"`<>\uE000]*)?/g,
      "$1",
    );
}

function tokenCouldForm(
  token,
  target,
  { allowFullyDynamic = false, minimumLiteralLength = 1 } = {},
) {
  if (token === target) {
    return true;
  }
  if (!token.includes(EXPANSION_MARKER)) {
    return false;
  }
  const skeleton = token.replaceAll(EXPANSION_MARKER, "");
  return (
    (allowFullyDynamic && !skeleton) ||
    (
      skeleton.length >= minimumLiteralLength &&
      isSubsequence(skeleton, target)
    )
  );
}

function expansionMarkerVariants(marked, issues) {
  const markerCount = [...marked].filter(
    (character) => character === EXPANSION_MARKER,
  ).length;
  if (markerCount > 10) {
    issues.add("too many interacting shell expansions in non-installable documentation");
    return [marked];
  }

  const variants = [];
  for (let mask = 0; mask < 2 ** markerCount; mask += 1) {
    let markerIndex = 0;
    let variant = "";
    for (const character of marked) {
      if (character !== EXPANSION_MARKER) {
        variant += character;
        continue;
      }
      variant += (mask & (1 << markerIndex)) === 0 ? EXPANSION_MARKER : " ";
      markerIndex += 1;
    }
    variants.push(variant);
  }
  return variants;
}

function flagPotentialInstallerComposition(value, spans, issues) {
  if (spans.length === 0) {
    return;
  }
  const marked = normalizedAuthorityText(
    joinLiteralObfuscators(replaceSpans(value, spans, EXPANSION_MARKER)),
  );
  for (const variant of expansionMarkerVariants(marked, issues)) {
    const tokens = variant.match(/[a-z0-9_\uE000]+/g) || [];
    for (let index = 0; index < tokens.length; index += 1) {
      const authority = tokens[index];
      const action = tokens[index + 1] || "";
      if (
        (
          tokenCouldForm(authority, "skills", {
            allowFullyDynamic: true,
            minimumLiteralLength: minimumAuthorityEvidence("skills"),
          }) &&
          ["add", "install", "update"].some((candidate) =>
            tokenCouldForm(action, candidate, { allowFullyDynamic: true }))
        ) ||
        (
          tokenCouldForm(authority, "clawhub", {
            allowFullyDynamic: true,
            minimumLiteralLength: minimumAuthorityEvidence("clawhub"),
          }) &&
          tokenCouldForm(action, "install", { allowFullyDynamic: true })
        ) ||
        tokenCouldForm(authority, "install_skill", {
          minimumLiteralLength: minimumAuthorityEvidence("install_skill"),
        })
      ) {
        issues.add("ambiguous dynamic public installer authority and action");
      }
    }
  }
}

function expansionBody(expansion) {
  if (
    expansion.startsWith("${") ||
    expansion.startsWith("$(") ||
    expansion.startsWith("$'") ||
    expansion.startsWith('$"')
  ) {
    return expansion.slice(2, -1);
  }
  if (expansion.startsWith("`")) {
    return expansion.slice(1, -1);
  }
  return "";
}

function flagInstallerWithinExpansion(value, spans, issues, depth = 0) {
  if (depth >= 8) {
    issues.add("excessively nested shell expansion in non-installable documentation");
    return;
  }
  for (const span of spans) {
    const body = expansionBody(value.slice(span.start, span.end + 1));
    if (!body) {
      continue;
    }
    scanAuthorityTails(body, issues);
    scanAuthorityTails(joinLiteralObfuscators(body), issues);
    const innerSpans = shellExpansionSpans(body);
    flagPotentialInstallerComposition(body, innerSpans, issues);
    if (innerSpans.length > 0) {
      flagInstallerWithinExpansion(body, innerSpans, issues, depth + 1);
    }
  }
}

function flagAmbiguousInstallerTail(value, spans, issues) {
  if (spans.length === 0) {
    return;
  }
  const marked = normalizedAuthorityText(
    joinLiteralObfuscators(replaceSpans(value, spans, EXPANSION_MARKER)),
  );
  const tokens = marked.match(/[a-z0-9_\uE000]+/g) || [];
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    const next = tokens[index + 1] || "";
    const markerCount = [...token].filter((character) => character === EXPANSION_MARKER).length;
    const skeleton = token.replaceAll(EXPANSION_MARKER, "");
    const dynamicAction = ["add", "install", "update"].some(
      (action) => skeleton && isSubsequence(skeleton, action),
    );
    if (markerCount >= 2 && (!skeleton || dynamicAction)) {
      issues.add("ambiguous dynamic public installer authority");
    } else if (
      ["skills", "clawhub"].includes(token) &&
      next.includes(EXPANSION_MARKER)
    ) {
      issues.add("ambiguous public installer action after installer authority");
    } else if (
      token === EXPANSION_MARKER &&
      (next === EXPANSION_MARKER || ["add", "install", "update"].includes(next))
    ) {
      issues.add("ambiguous dynamic public installer authority");
    }
  }
}

function expansionViews(value, issues) {
  const spans = shellExpansionSpans(value);
  const descriptors = spans.map((span) =>
    staticallyKnownExpansion(value.slice(span.start, span.end + 1)));
  const hasBoundedStaticExpansion = descriptors.some(
    (descriptor) => descriptor && !descriptor.canBeUnknown,
  );
  if (!hasBoundedStaticExpansion) {
    flagAmbiguousAuthorityFragments(value, spans, issues);
    flagPotentialInstallerComposition(value, spans, issues);
    flagAmbiguousInstallerTail(value, spans, issues);
  }
  flagInstallerWithinExpansion(value, spans, issues);
  return [
    value,
    ...staticallyKnownExpansionViews(value, spans, issues),
    replaceSpans(value, spans, ""),
    replaceSpans(value, spans, " "),
  ];
}

function collectExpansionSurfaces(initial, issues) {
  const surfaces = new Set();
  const queue = [initial];

  while (queue.length > 0) {
    const value = queue.shift();
    if (surfaces.has(value)) {
      continue;
    }
    if (surfaces.size >= 64) {
      issues.add("too many interacting documentation decoding surfaces");
      break;
    }
    surfaces.add(value);
    validateCharacters(value, issues);
    validateShellSyntaxPolicy(value, issues);

    const spans = shellExpansionSpans(value);
    const hasBoundedStaticExpansion = spans.some((span) => {
      const descriptor = staticallyKnownExpansion(
        value.slice(span.start, span.end + 1),
      );
      return descriptor && !descriptor.canBeUnknown;
    });
    if (!hasBoundedStaticExpansion) {
      const quotedToken = shellQuotedTokenView(value);
      if (!surfaces.has(quotedToken)) {
        queue.push(quotedToken);
      }
      const joined = joinLiteralObfuscators(value);
      if (!surfaces.has(joined)) {
        queue.push(joined);
      }
    }
    for (const expanded of expansionViews(value, issues)) {
      if (!surfaces.has(expanded)) {
        queue.push(expanded);
      }
    }
  }

  return surfaces;
}

function authorityTokens(value) {
  const versionless = normalizedAuthorityText(value);
  return versionless.match(/[a-z0-9_]+/g) || [];
}

function scanAuthorityTails(value, issues) {
  const tokens = authorityTokens(value);
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    const next = tokens[index + 1] || "";
    if (token === "skills" && ["add", "install", "update"].includes(next)) {
      issues.add(`forbidden public installer authority: skills ${next}`);
    } else if (token === "clawhub" && next === "install") {
      issues.add("forbidden public installer authority: clawhub install");
    } else if (token === "install_skill") {
      issues.add("forbidden public installer authority: install_skill");
    }
  }
}

function executableName(token) {
  const basename = token
    .normalize("NFKC")
    .toLowerCase()
    .split(/[\\/]/)
    .at(-1);
  return (basename || "")
    .replace(/\.(?:cmd|exe|ps1)$/i, "")
    .replace(/@[^@/]+$/, "");
}

function isRemotePackageUrl(token) {
  return /^[a-z][a-z0-9+.-]*:\/\/\S+$/i.test(token);
}

function shellCommandWordGroups(value) {
  const groups = [];
  let words = [];
  let word = "";
  let quote = "";

  const appendProtected = (character) => {
    word += /[\s'"`<>]/u.test(character) ? "_" : character;
  };
  const flushWord = () => {
    if (word) {
      words.push(word);
      word = "";
    }
  };
  const flushGroup = () => {
    flushWord();
    if (words.length > 0) {
      groups.push(words);
      words = [];
    }
  };

  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (quote) {
      if (character === quote) {
        quote = "";
      } else if (
        quote === '"' &&
        character === "\\" &&
        index + 1 < value.length &&
        ['$', "`", '"', "\\", "\n"].includes(value[index + 1])
      ) {
        const escaped = value[index + 1];
        if (escaped !== "\n") {
          appendProtected(escaped);
        }
        index += 1;
      } else {
        appendProtected(character);
      }
      continue;
    }

    if (character === "\\" && index + 1 < value.length) {
      const escaped = value[index + 1];
      if (escaped !== "\n") {
        appendProtected(escaped);
      }
      index += 1;
    } else if (character === "#" && word === "") {
      flushGroup();
      const newline = value.indexOf("\n", index + 1);
      if (newline === -1) {
        break;
      }
      index = newline;
    } else if (character === "'" || character === '"') {
      quote = character;
    } else if (character === "\n" || /[;&|()]/.test(character)) {
      flushGroup();
    } else if (/\s/u.test(character)) {
      flushWord();
    } else {
      word += character;
    }
  }
  flushGroup();

  return groups;
}

function scanUrlExecutorTails(value, issues) {
  for (const words of shellCommandWordGroups(value.normalize("NFKC"))) {
    for (let index = 0; index < words.length; index += 1) {
      const command = executableName(words[index]);
      let launcher = "";
      let cursor = index + 1;

      if (["npx", "bunx", "pnpx"].includes(command)) {
        launcher = command;
      } else if (
        ["npm", "pnpm", "yarn"].includes(command) &&
        ["exec", "dlx"].includes(executableName(words[cursor] || ""))
      ) {
        launcher = `${command} ${executableName(words[cursor])}`;
        cursor += 1;
      } else {
        continue;
      }

      for (; cursor < words.length; cursor += 1) {
        if (!isRemotePackageUrl(words[cursor])) {
          continue;
        }
        let actionIndex = cursor + 1;
        while (words[actionIndex] === "--") {
          actionIndex += 1;
        }
        const action = executableName(words[actionIndex] || "");
        if (["add", "install", "update"].includes(action)) {
          issues.add(
            `forbidden remote package executor with installer action: ${launcher} URL ${action}`,
          );
        }
        break;
      }
    }
  }
}

export function inspectNonInstallableMarkdown(input) {
  const issues = new Set();
  const markdown = decodeMarkdown(input, issues);
  if (markdown === null) {
    return { markdown: null, issues: [...issues] };
  }

  const lineNormalized = markdown
    .replace(/^\uFEFF/, "")
    .replace(/\r\n?/g, "\n");
  validateCharacters(lineNormalized, issues);
  validateMarkdownLinkPolicy(lineNormalized, issues);
  validateShellSyntaxPolicy(lineNormalized, issues);

  const normalized = lineNormalized.normalize("NFKC");
  const structuralBases = new Set([normalized, ...markupViews(normalized, issues)]);

  const bases = new Set();
  for (const structuralBase of structuralBases) {
    const decoded = decodeEntities(structuralBase, issues);
    validateCharacters(decoded, issues);
    bases.add(decoded.normalize("NFKC"));
  }

  const surfaces = new Set();
  for (const base of bases) {
    const shellBase = projectMarkdownFences(base, issues);
    for (const surface of collectExpansionSurfaces(shellBase, issues)) {
      surfaces.add(surface);
    }
  }
  for (const surface of surfaces) {
    scanAuthorityTails(surface, issues);
    scanUrlExecutorTails(surface, issues);
  }

  return {
    markdown,
    issues: [...issues],
  };
}
