import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { inspectNonInstallableMarkdown } from "./ci/noninstallable_public_installer_policy.mjs";

for (const [label, markdown, expectedIssue] of [
  ["canonical skills add", "npx skills add prompt-security/clawsec", "skills add"],
  ["quoted versioned command", `"npx@10" 'skills@latest' "add" target`, "skills add"],
  ["npm exec update", "npm exec -- skills update target", "skills update"],
  ["pnpm clawhub", "pnpm dlx clawhub@latest install target", "clawhub install"],
  ["direct clawhub", "clawhub install target", "clawhub install"],
  ["Hermes installer", "hermes skills install target", "skills install"],
  ["Pico installer", "install_skill(target)", "install_skill"],
  ["shell escaped", "s\\kills a\\d\\d target", "skills add"],
  ["two-layer shell escaped", "s\\\\kills add target", "skills add"],
  [
    "Markdown-unescaped expansion introducers",
    "$\\{x:-skills} $\\{y:-add}",
    "ambiguous dynamic public installer authority and action",
  ],
  [
    "command substitution policy",
    '$(printf "sk%slls add" i) target',
    "command substitution",
  ],
  [
    "legacy backtick substitution policy",
    "`printf 'sk%slls add' i` target",
    "non-fence backticks",
  ],
  [
    "invalid closing fence content",
    "```text\nsafe\n``` skills add target\n```",
    "non-fence backticks",
  ],
  [
    "shorter backticks inside longer fence",
    "````text\n```skills add target\n````",
    "non-fence backticks",
  ],
  [
    "backtick content inside tilde fence",
    "~~~text\n``` literal content\n~~~",
    "non-fence backticks",
  ],
  [
    "installer tail in fence info string",
    "```skills add target\nsafe\n```",
    "skills add",
  ],
  [
    "ClawHub tail in longer fence info string",
    "````clawhub install target\nsafe\n````",
    "clawhub install",
  ],
  [
    "installer tail in tilde fence info string",
    "~~~skills add target\nsafe\n~~~",
    "skills add",
  ],
  [
    "invalid tilde closing fence content",
    "~~~text\nsafe\n~~~ skills add target\n~~~",
    "skills add",
  ],
  ["quote fragmented", `s'k'ills a"d"d target`, "skills add"],
  ["line continuation", "skills \\\nadd target", "skills add"],
  ["arbitrary gap", `skills${" -".repeat(400)} add target`, "skills add"],
  ["hidden comment", "<!-- npx skills add target -->", "skills add"],
  ["comment split", "sk<!-- noise -->ills add target", "skills add"],
  ["tag wrapped", "<code>skills</code><span>add</span>", "skills add"],
  [
    "tag obfuscation after prose apostrophe",
    "Don't allow this: sk<x>ill</x>s add target",
    "skills add",
  ],
  [
    "tag obfuscation after prior-line prose apostrophe",
    "Ordinary user's note\nsk<x>ill</x>s add target",
    "skills add",
  ],
  [
    "tag obfuscation after unmatched prose quote",
    'Prose says "warning: skills a<span>d</span>d target',
    "skills add",
  ],
  [
    "unterminated tag after prose apostrophe",
    "Don't allow this: sk<x",
    "unterminated HTML tag",
  ],
  ["numeric entities", "sk&#105;lls&#x20;add target", "skills add"],
  ["double entities", "sk&amp;#105;lls&amp;#x20;add target", "skills add"],
  ["full-width", "ｓｋｉｌｌｓ ａｄｄ target", "skills add"],
  ["ASCII hex escape", "sk\\x69lls add target", "skills add"],
  ["ASCII Unicode escape", "sk\\u0069lls add target", "skills add"],
  ["empty expansion", "sk${EMPTY}ills add target", "skills add"],
  ["spacing expansion", "skills${SPACE}add target", "skills add"],
  [
    "ANSI-C octal fragment",
    "$'\\163\\153\\151'lls add target",
    "skills add",
  ],
  [
    "ANSI-C long Unicode fragment",
    "claw$'\\U00000068\\U00000075\\U00000062' install target",
    "clawhub install",
  ],
  [
    "ANSI-C zero-prefixed octal control",
    "echo $'\\0163'",
    "control",
  ],
  ["ANSI-C fragment", "sk$'i'lls add target", "skills add"],
  ["ANSI-C boundary fragment", "skill$'s' add target", "skills add"],
  ["fully quoted ANSI-C authority", "$'skills' add target", "skills add"],
  [
    "fully dynamic authority and action",
    "${tool:-skills} ${action:-add} target",
    "ambiguous dynamic public installer authority",
  ],
  [
    "fully dynamic authority and action through IFS",
    "${tool:-skills}${IFS}${action:-add} target",
    "ambiguous dynamic public installer authority",
  ],
  [
    "dynamic authority through IFS with literal action",
    "$tool${IFS}add target",
    "ambiguous dynamic public installer authority",
  ],
  [
    "fragmented authority before IFS",
    "sk${mid:-i}lls${IFS}add target",
    "ambiguous dynamic public installer authority and action",
  ],
  [
    "nested fragmented authority before IFS",
    "${cmd:-sk${mid:-i}lls${IFS}add} target",
    "ambiguous dynamic public installer authority and action",
  ],
  [
    "installer tail inside a parameter default",
    "${cmd:-skills${IFS}add} target",
    "ambiguous dynamic public installer authority and action",
  ],
  [
    "installer tail inside ANSI-C quoting",
    "$'skills add' target",
    "skills add",
  ],
  ["parameter default fragment", "sk${value:-i}lls add target", "ambiguous public installer authority"],
  [
    "nested parameter fragment",
    "sk${outer:-${inner:-i}}lls add target",
    "ambiguous public installer authority",
  ],
  [
    "near-complete Skills authority fragment",
    "skil${suffix} add target",
    "ambiguous public installer authority",
  ],
  [
    "near-complete ClawHub authority fragment",
    "clawh${suffix} install target",
    "ambiguous public installer authority",
  ],
  [
    "near-complete Pico authority fragment",
    "install_ski${suffix} target",
    "ambiguous public installer authority",
  ],
  [
    "known parameter default completes Skills authority",
    "s${value:-kills} add target",
    "skills add",
  ],
  [
    "known parameter default completes ClawHub authority",
    "c${value:-lawhub} install target",
    "clawhub install",
  ],
  [
    "known parameter default completes Pico authority",
    "i${value:-nstall_skill} target",
    "install_skill",
  ],
  [
    "known ANSI-C string completes Skills authority",
    "s$'kills' add target",
    "skills add",
  ],
  [
    "known localized string completes Skills authority",
    's$"kills" add target',
    "skills add",
  ],
  [
    "nested known defaults complete Skills authority",
    "s${value:-k${tail:-ills}} add target",
    "skills add",
  ],
  [
    "known expansion subset omits conditional noise",
    "${noise:+x}${tool:-skills} ${action:-add} target",
    "skills add",
  ],
  [
    "known expansions compose through unknown separator",
    "${tool:-skills}${IFS}${action:-add} target",
    "skills add",
  ],
  ["positional parameter fragment", "sk$1ills add target", "ambiguous public installer authority"],
  ["command substitution fragment", "sk$(printf i)lls add target", "ambiguous public installer authority"],
  ["action substitution", "skills $(printf add) target", "ambiguous public installer action"],
  ["parameter action", "skills ${verb:-add} target", "ambiguous public installer action"],
  [
    "nested parameter action",
    "skills ${outer:-${verb:-add}} target",
    "ambiguous public installer action",
  ],
  ["positional action", "skills $1 target", "ambiguous public installer action"],
  ["hash version package", "skills#v1 add target", "skills add"],
  [
    "Git HTTPS fragment package",
    "https://github.com/vercel-labs/skills.git#v1 add target",
    "skills add",
  ],
  [
    "bare Git HTTPS package",
    "npx https://github.com/vercel-labs/skills.git add target",
    "skills add",
  ],
  ["percent-encoded package", "npx https://example.test/%73kills.git#v1 add target", "skills add"],
  [
    "registry tarball package",
    "npx https://registry.example.test/skills/-/skills-1.2.3.tgz add target",
    "skills add",
  ],
  [
    "percent-encoded registry tarball package",
    "npx https://registry.example.test/%73kills/-/%73kills-1.2.3.tgz add target",
    "skills add",
  ],
  [
    "registry tarball package with query",
    "npx --yes 'https://registry.npmjs.org/skills/-/skills-1.5.20.tgz?cache=1' add target",
    "skills add",
  ],
  [
    "registry tarball package with query and fragment",
    "npx --yes 'https://registry.npmjs.org/skills/-/skills-1.5.20.tgz?cache=1#v1' add target",
    "skills add",
  ],
  [
    "registry tarball package with arbitrary path suffix",
    "npx --yes http://example.test/skills/-/skills-1.2.3.tgz/extra add target",
    "remote package executor",
  ],
  [
    "registry tarball package with encoded path suffix",
    "npx --yes http://example.test/skills/-/skills-1.2.3.tgz%2Fextra add target",
    "remote package executor",
  ],
  [
    "registry tarball package with semicolon suffix",
    "npx --yes 'http://example.test/skills/-/skills-1.2.3.tgz;extra' add target",
    "remote package executor",
  ],
  [
    "registry tarball package with repeated slash suffix",
    "npx --yes http://example.test/skills/-/skills-1.2.3.tgz//extra add target",
    "remote package executor",
  ],
  [
    "registry tarball package with comma suffix",
    "npx --yes http://example.test/skills/-/skills-1.2.3.tgz,extra add target",
    "remote package executor",
  ],
  [
    "opaque Git URL through npx",
    "npx --yes 'git+https://example.test/widget A.git#v1' add target",
    "remote package executor",
  ],
  [
    "opaque URL through bunx",
    "bunx https://example.test/widget.tgz install target",
    "remote package executor",
  ],
  [
    "opaque URL through npm exec",
    "npm exec -- https://example.test/widget.tgz -- update target",
    "remote package executor",
  ],
  [
    "opaque URL through pnpm dlx",
    "pnpm dlx https://example.test/widget.tgz add target",
    "remote package executor",
  ],
  [
    "opaque URL through yarn dlx",
    "yarn dlx https://example.test/widget.tgz install target",
    "remote package executor",
  ],
  [
    "opaque URL after many executor flags",
    `npx ${"--yes ".repeat(20)}https://example.test/widget.tgz add target`,
    "remote package executor",
  ],
  [
    "opaque quoted URL with literal semicolon",
    "npx 'https://example.test/widget;extra' add target",
    "remote package executor",
  ],
  [
    "opaque URL with shell-escaped semicolon",
    "npx https://example.test/widget\\;extra add target",
    "remote package executor",
  ],
  [
    "opaque URL after line continuation",
    "npx --yes \\\nhttps://example.test/widget.tgz update target",
    "remote package executor",
  ],
  [
    "registry tarball package with semicolon query",
    "npx --yes 'https://registry.npmjs.org/skills/-/skills-1.5.20.tgz?cache=1;foo=2' add target",
    "skills add",
  ],
  [
    "registry tarball package with legal query punctuation",
    "npx --yes 'https://registry.npmjs.org/skills/-/skills-1.5.20.tgz?cache=1?more=2,@!()' add target",
    "skills add",
  ],
  [
    "registry tarball package with encoded semicolon query",
    "npx --yes 'https://registry.npmjs.org/skills/-/skills-1.5.20.tgz?cache=1%3Bfoo=2' add target",
    "skills add",
  ],
  [
    "registry tarball package with fragment punctuation",
    "npx --yes 'https://registry.npmjs.org/skills/-/skills-1.5.20.tgz#a!z' add target",
    "skills add",
  ],
  [
    "registry tarball package with encoded fragment punctuation",
    "npx --yes 'https://registry.npmjs.org/skills/-/skills-1.5.20.tgz%23%61%21%7A' add target",
    "skills add",
  ],
  [
    "registry tarball package with double-encoded fragment punctuation",
    "npx --yes 'https://registry.npmjs.org/skills/-/skills-1.5.20.tgz%2523%2561%2521%257A' add target",
    "skills add",
  ],
  [
    "Git package with fragment punctuation",
    "npx https://github.com/vercel-labs/skills.git#a!z add target",
    "skills add",
  ],
  [
    "registry tarball package with encoded space",
    "npx --yes 'https://registry.npmjs.org/skills/-/skills-1.5.20.tgz?cache=1%20foo=2' add target",
    "percent-encoded syntax delimiter",
  ],
  [
    "registry tarball package with double-encoded space",
    "npx --yes 'https://registry.npmjs.org/skills/-/skills-1.5.20.tgz?cache=1%2520foo=2' add target",
    "percent-encoded syntax delimiter",
  ],
  [
    "registry tarball package with encoded angle delimiter",
    "npx --yes 'https://registry.npmjs.org/skills/-/skills-1.5.20.tgz?cache=1%3Efoo=2' add target",
    "percent-encoded syntax delimiter",
  ],
  [
    "registry tarball package with numeric entity space",
    "npx --yes 'https://registry.npmjs.org/skills/-/skills-1.5.20.tgz?cache=1&#32;foo=2' add target",
    "HTML-encoded syntax delimiter",
  ],
  [
    "registry tarball package with hexadecimal entity space",
    "npx --yes 'https://registry.npmjs.org/skills/-/skills-1.5.20.tgz?cache=1&#x20;foo=2' add target",
    "HTML-encoded syntax delimiter",
  ],
  [
    "registry tarball package with nested entity space",
    "npx --yes 'https://registry.npmjs.org/skills/-/skills-1.5.20.tgz?cache=1&amp;#32;foo=2' add target",
    "HTML-encoded syntax delimiter",
  ],
  [
    "registry tarball package with compatibility angle delimiter",
    "npx --yes 'https://registry.npmjs.org/skills/-/skills-1.5.20.tgz?cache=1＜foo=2' add target",
    "compatibility character",
  ],
  [
    "registry tarball package with encoded compatibility angle delimiter",
    "npx --yes 'https://registry.npmjs.org/skills/-/skills-1.5.20.tgz?cache=1%EF%BC%9Cfoo=2' add target",
    "compatibility character",
  ],
  [
    "registry tarball package with safe dollar query still installs",
    "npx --yes 'https://registry.npmjs.org/skills/-/skills-1.5.20.tgz?cache=A%24B' add target",
    "skills add",
  ],
  [
    "quoted registry tarball package with raw space",
    'npx --yes "https://registry.npmjs.org/skills/-/skills-1.5.20.tgz?cache=A B" add target',
    "skills add",
  ],
  [
    "quoted registry tarball package with raw angle delimiter",
    'npx --yes "https://registry.npmjs.org/skills/-/skills-1.5.20.tgz?cache=A>B" add target',
    "skills add",
  ],
  [
    "single-quoted registry tarball with raw double quote",
    "npx --yes 'https://registry.npmjs.org/skills/-/skills-1.5.20.tgz?cache=A\"B' add target",
    "skills add",
  ],
  [
    "registry tarball with shell-escaped space",
    "npx --yes https://registry.npmjs.org/skills/-/skills-1.5.20.tgz?cache=A\\ B add target",
    "skills add",
  ],
  [
    "registry tarball with shell-escaped angle",
    "npx --yes https://registry.npmjs.org/skills/-/skills-1.5.20.tgz?cache=A\\>B add target",
    "skills add",
  ],
  [
    "registry tarball with line continuation",
    "npx --yes https://registry.npmjs.org/skills/-/skills-1.5.20.tgz?cache=A\\\nB add target",
    "skills add",
  ],
  [
    "Git package with shell-escaped space",
    "npx https://github.com/vercel-labs/skills.git?q=A\\ B add target",
    "skills add",
  ],
  [
    "registry tarball package with encoded fragment",
    "npx --yes 'https://registry.npmjs.org/skills/-/skills-1.5.20.tgz?cache=1%23v1' add target",
    "skills add",
  ],
  ["Windows cmd executable", "skills.cmd add target", "skills add"],
  ["Windows exe executable", "skills.exe update target", "skills update"],
  ["PowerShell executable", "skills.ps1 install target", "skills install"],
  ["JavaScript executable", "./skills.js add target", "skills add"],
  ["ES module executable", "./skills.mjs add target", "skills add"],
  ["Python executable", "./skills.py install target", "skills install"],
  ["shell executable", "./skills.sh update target", "skills update"],
  ["DOS executable", "./skills.com add target", "skills add"],
  ["ClawHub executable", "clawhub.cmd install target", "clawhub install"],
  [
    "Markdown links",
    "[skills](https://example.test/a) [add](https://example.test/b)",
    "Markdown links and images",
  ],
  [
    "deeply nested Markdown links",
    "[skills](https://x/(a(b))) [add](https://x/) target",
    "Markdown links and images",
  ],
  [
    "angle-bracket Markdown destination",
    "[skills](<(noise>) [add](x)",
    "Markdown links and images",
  ],
  [
    "multiline angle-bracket Markdown destination",
    "[skills](<(a>\n) [add](x)",
    "Markdown links and images",
  ],
  [
    "angle-bracket Markdown destination after newline",
    "[skills](\n<(a>) [add](x)",
    "Markdown links and images",
  ],
  ["quote inside Markdown label", '[sk"]()ills" add', "Markdown links and images"],
  [
    "quote inside Markdown reference label",
    '[skills][a"] [add][b]\n\n[a"]: /x\n[b]: /y',
    "Markdown links and images",
  ],
  [
    "entity in Markdown destination",
    "[skills](https://x/&#41;noise) [add](https://x/)",
    "Markdown links and images",
  ],
  [
    "double entity in Markdown destination",
    "[skills](https://x/&amp;#41;noise) [add](https://x/)",
    "Markdown links and images",
  ],
  [
    "nested Markdown image",
    "[skills![](x)]() add",
    "Markdown links and images",
  ],
  [
    "blockquote reference definition",
    "skills\n> [a]: x\nadd",
    "Markdown links and images",
  ],
  [
    "nested blockquote reference definition",
    "skills\n>> [a]: x\nadd",
    "Markdown links and images",
  ],
  [
    "list reference definition",
    "skills\n- [a]: x\nadd",
    "Markdown links and images",
  ],
  [
    "blockquote shortcut reference",
    '> [sk"]ills" add\n>\n> [sk"]: /x',
    "Markdown links and images",
  ],
  ["Markdown URI autolink", "<https://example.test/docs>", "Markdown links and images"],
  ["Markdown email autolink", "<security@example.test>", "Markdown links and images"],
  ["HTML anchor", '<a href="https://example.test">docs</a>', "Markdown links and images"],
  ["HTML image", '<img src="https://example.test/x.png">', "Markdown links and images"],
  ["HTML image alias", '<image src="https://example.test/x.png">', "Markdown links and images"],
  [
    "escaped-bracket reference definition",
    "[\\]]:a\n[\\]]",
    "Markdown links and images",
  ],
  ["entity inside HTML comment", "sk<!-- --&gt; -->ills add", "skills add"],
  ["entity inside HTML tag", "sk<x a=&gt;>ills add", "skills add"],
  ["zero-width split", "sk\u200bills add target", "formatting character"],
  ["variation selector split", "sk\uFE0Fills add target", "default-ignorable"],
  ["combining grapheme joiner split", "sk\u034Fills add target", "default-ignorable"],
  ["bidirectional control", "skills\u202e add target", "formatting character"],
  ["non-ASCII whitespace", "skills\u00a0add target", "non-ASCII whitespace"],
  ["unknown entity", "safe &unknown; prose", "unsupported"],
  ["unterminated comment", "safe <!-- comment", "unterminated HTML comment"],
]) {
  const result = inspectNonInstallableMarkdown(markdown);
  assert.ok(result.issues.length > 0, `${label} must be rejected`);
  assert.match(
    result.issues.join("\n"),
    new RegExp(expectedIssue, "i"),
    `${label} must report ${expectedIssue}`,
  );
}

const invalidUtf8 = inspectNonInstallableMarkdown(Buffer.from([0xc3, 0x28]));
assert.equal(invalidUtf8.markdown, null);
assert.match(invalidUtf8.issues.join("\n"), /not valid UTF-8/);

for (const [label, markdown] of [
  ["internal release helper", "./scripts/release-skill.sh <name> 1.2.0-rc1"],
  ["Git operations", "git status\ngit add path\ngit push origin branch"],
  ["GitHub release inspection", "gh release view tag"],
  ["verification tools", "curl URL -o file\nopenssl version\njq --version\nshasum -a 256 file"],
  ["development tools", "npm ci\nnpx eslint .\nnpx tsc --noEmit\npipx run ruff check"],
  ["ClawHub release operations", "clawhub inspect\nclawhub login\nclawhub publish"],
  ["read-only skill operations", "skills list\nhermes skills list\nfind_skills(query)"],
  ["read-only dynamic filter", "skills list ${FILTER}"],
  ["read-only dynamic command", "$tool list"],
  ["OpenClaw cron", "openclaw cron add --name advisory-check"],
  ["denial prose", "Installation is unavailable through public skill channels."],
  ["unrelated words", "Skills are safe to add only after independent review."],
  ["non-authority identifier", "install_skillful is not the Pico installer function."],
  ["core entity", "\uFEFFUse A &amp; B.\r\n"],
  ["plain URL", "See https://example.test/docs for details."],
  ["plain IPv6 URL", "See http://[::1]:8080/docs for details."],
  ["plain expanded IPv6 URL", "See https://[2001:db8::1]:443/path for details."],
  ["plain IPv6 curl command", "curl http://[::1]:3000/feed.json -o feed.json"],
  ["safe fenced code", "```bash\ngit status\n```"],
  ["safe fenced variable", '```bash\nprintf "%s\\n" "${HOME}"\n```'],
  ["safe four-backtick fence", "````bash\ngit status\n````"],
  ["safe four-backtick variable", '````bash\nprintf "%s\\n" "${HOME}"\n````'],
  ["safe tilde fence", "~~~bash\ngit status\n~~~"],
  ["safe tilde variable", '~~~bash\nprintf "%s\\n" "${HOME}"\n~~~'],
  ["safe percent-encoded URL path", "See https://example.test/a%2Fb for details."],
  ["safe numeric-entity URL path", "See https://example.test/a&#47;b for details."],
  ["safe raw dollar URL query", "See https://example.test/archive.tgz?x=A$B for details."],
  ["safe encoded dollar URL query", "See https://example.test/archive.tgz?x=A%24B for details."],
  ["safe double-encoded dollar URL query", "See https://example.test/archive.tgz?x=A%2524B for details."],
  ["safe entity dollar URL path", "See https://example.test/a&#36;b for details."],
  ["safe compatibility dollar URL path", "See https://example.test/a＄b for details."],
  ["safe short authority subsequence URL", "See https://example.test/in$B for details."],
  [
    "safe quoted curl dollar URL",
    "```bash\ncurl 'https://example.test/archive.tgz?x=A%24B' -o package.tgz\n```",
  ],
  [
    "safe quoted curl URL with raw space",
    "```bash\ncurl 'https://example.test/archive.tgz?x=A B' -o package.tgz\n```",
  ],
  [
    "safe curl URL with shell-escaped space",
    "```bash\ncurl https://example.test/archive.tgz?x=A\\ B -o package.tgz\n```",
  ],
  [
    "safe curl URL with line continuation",
    "```bash\ncurl https://example.test/archive.tgz?x=A\\\nB -o package.tgz\n```",
  ],
  [
    "safe quoted curl URL with literal less-than",
    "```bash\ncurl 'https://example.test/archive.tgz?q=A<B' -o package.tgz\n```",
  ],
  [
    "safe curl URL with shell-escaped less-than",
    "```bash\ncurl https://example.test/archive.tgz?q=A\\<B -o package.tgz\n```",
  ],
  ["safe exact conditional expansions", "echo ${a:+one}${b:+two}"],
  ["safe exact non-colon conditional expansions", "echo ${a+one}${b+two}"],
  [
    "safe four exact conditional expansions",
    "echo ${a:+one}${b:+two}${c:+three}${d:+four}",
  ],
  ["safe adjacent ANSI-C strings", "echo $'one'$'two'"],
  [
    "safe mixed exact shell expansions",
    "echo ${a:+one}$'two'${b:+three}",
  ],
  ["safe literal octal outside ANSI-C quoting", "printf '%s\\n' '\\163\\153\\151'"],
  ["safe literal U8 outside ANSI-C quoting", "printf '%s\\n' '\\U00000073'"],
  ["safe three-digit zero-prefixed ANSI octal", "echo $'\\060123'"],
  ["safe longer identifier", "skillsful add target"],
  [
    "safe URL executor with non-sensitive action",
    "npx https://example.test/widget.tgz status",
  ],
  [
    "safe URL executor with many flags and non-sensitive action",
    `npx ${"--yes ".repeat(20)}https://example.test/widget.tgz status`,
  ],
  [
    "safe attached semicolon command boundary",
    "npx --yes; curl https://example.test/widget.bin add target",
  ],
  [
    "safe attached AND command boundary",
    "npx --yes&& curl https://example.test/widget.bin add target",
  ],
  [
    "safe attached OR command boundary",
    "npx --yes|| curl https://example.test/widget.bin add target",
  ],
  [
    "safe attached pipe command boundary",
    "npx --yes| curl https://example.test/widget.bin add target",
  ],
  [
    "safe newline command boundary",
    "npx --yes\ncurl https://example.test/widget.bin add target",
  ],
  [
    "safe URL-attached semicolon command boundary",
    "npx --yes https://example.test/widget.bin; add target",
  ],
  [
    "safe URL-attached AND command boundary",
    "npx --yes https://example.test/widget.bin&& add target",
  ],
  [
    "safe shell comment after executor",
    "npx --yes # https://example.test/widget.tgz add target",
  ],
  [
    "safe shell comment before later curl command",
    "npx --yes # ignored URL and action\ncurl https://example.test/widget.bin add target",
  ],
]) {
  const result = inspectNonInstallableMarkdown(markdown);
  assert.deepEqual(result.issues, [], `${label} must remain allowed: ${result.issues.join("; ")}`);
}
