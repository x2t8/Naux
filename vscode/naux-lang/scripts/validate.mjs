import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const packageJson = readJson(join(packageRoot, "package.json"));
const identity = readJson(join(packageRoot, "linguist-language.json"));
const grammar = readJson(join(packageRoot, identity.grammar));
const iconTheme = readJson(join(packageRoot, "icons/naux-icon-theme.json"));
const languageConfiguration = readJson(join(packageRoot, "language-configuration.json"));

const expectedIdentity = {
  language: "NAUX",
  type: "programming",
  aliases: ["naux"],
  extensions: [".nx"],
  tmScope: "source.naux",
  aceMode: "text",
  color: "#FF304D",
  interpreters: ["naux"],
  grammar: "syntaxes/naux.tmLanguage.json",
  license: "MIT",
  status: "candidate-not-submitted"
};

assert.equal(identity.schemaVersion, 1, "unsupported identity schema");
for (const [field, expected] of Object.entries(expectedIdentity)) {
  assert.deepEqual(identity[field], expected, `identity drift: ${field}`);
}

assert.equal(packageJson.displayName, "NAUX Language");
assert.equal(packageJson.publisher, "x2t8");
assert.equal(packageJson.license, identity.license);
assert.equal(packageJson.preview, true, "Marketplace package must remain experimental");
assert.deepEqual(packageJson.galleryBanner, { color: "#111318", theme: "dark" });
assert.equal(packageJson.repository.url, "https://github.com/x2t8/naux-grammar.git");
assert.equal(packageJson.homepage, "https://github.com/x2t8/naux-grammar");
assert.equal(packageJson.dependencies, undefined, "grammar must remain dependency-free");
assert.equal(packageJson.devDependencies, undefined, "grammar must remain dependency-free");
assert.ok(
  existsSync(join(packageRoot, ".github/workflows/validate.yml")),
  "standalone validation workflow missing"
);
assert.ok(existsSync(join(packageRoot, "CHANGELOG.md")), "Marketplace changelog missing");
assert.ok(
  readFileSync(join(packageRoot, ".vscodeignore"), "utf8").includes(".github/**"),
  "VSIX package must exclude repository workflows"
);

const language = packageJson.contributes.languages.find(({ id }) => id === "naux");
assert.ok(language, "package must register the naux language id");
assert.deepEqual(language.aliases, ["NAUX", ...identity.aliases]);
assert.deepEqual(language.extensions, identity.extensions);

const grammarContribution = packageJson.contributes.grammars.find(
  ({ language: id }) => id === "naux"
);
assert.ok(grammarContribution, "package must contribute the NAUX grammar");
assert.equal(grammarContribution.scopeName, identity.tmScope);
assert.equal(grammarContribution.path, `./${identity.grammar}`);
assert.equal(grammar.name, identity.language);
assert.equal(grammar.scopeName, identity.tmScope);
assert.deepEqual(grammar.fileTypes, ["nx"]);
assert.equal(iconTheme.fileExtensions.nx, "naux");
assert.equal(iconTheme.languageIds.naux, "naux");
assert.ok(existsSync(join(packageRoot, packageJson.icon)), "package icon missing");
assert.ok(
  existsSync(join(packageRoot, "icons", iconTheme.iconDefinitions.naux.iconPath)),
  "file-theme icon missing"
);

const expectedLinguistEntry = `NAUX:
  type: programming
  color: "#FF304D"
  aliases:
  - naux
  extensions:
  - ".nx"
  interpreters:
  - naux
  tm_scope: source.naux
  ace_mode: text
`;
assert.equal(
  readFileSync(join(packageRoot, "linguist-entry.yml"), "utf8"),
  expectedLinguistEntry,
  "Linguist entry drift"
);

const requiredRepositories = [
  "comments",
  "strings",
  "bytes",
  "function-declarations",
  "block-keywords",
  "keywords",
  "actions",
  "types",
  "constants",
  "builtins",
  "variables",
  "map-keys",
  "function-calls",
  "numbers",
  "operators",
  "punctuation"
];
assert.deepEqual(Object.keys(grammar.repository), requiredRepositories);

const validateExpressions = (node, path = "grammar") => {
  if (Array.isArray(node)) {
    node.forEach((child, index) => validateExpressions(child, `${path}[${index}]`));
    return;
  }
  if (!node || typeof node !== "object") return;
  for (const [key, value] of Object.entries(node)) {
    if (["match", "begin", "end"].includes(key)) {
      assert.doesNotThrow(() => new RegExp(value, "u"), `invalid ${path}.${key}`);
    } else {
      validateExpressions(value, `${path}.${key}`);
    }
  }
};
validateExpressions(grammar);
for (const [label, expression] of Object.entries({
  wordPattern: languageConfiguration.wordPattern,
  increaseIndentPattern: languageConfiguration.indentationRules.increaseIndentPattern,
  decreaseIndentPattern: languageConfiguration.indentationRules.decreaseIndentPattern,
  foldingStart: languageConfiguration.folding.markers.start,
  foldingEnd: languageConfiguration.folding.markers.end
})) {
  assert.doesNotThrow(() => new RegExp(expression, "u"), `invalid ${label}`);
}

const constantPattern = grammar.repository.constants.patterns[0].match;
assert.ok(!constantPattern.includes("null"), "NAUX has no Surface null literal");

const publicBuiltinPattern = grammar.repository.builtins.patterns.find(
  ({ name }) => name === "support.function.builtin.naux"
).match;
const publicBuiltins = publicBuiltinPattern
  .replace(/^\\b\(/, "")
  .replace(/\)\\b$/, "")
  .split("|")
  .sort();
assert.equal(new Set(publicBuiltins).size, publicBuiltins.length, "duplicate builtin");

const walkRust = (directory) => {
  const files = [];
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) files.push(...walkRust(path));
    else if (path.endsWith(".rs")) files.push(path);
  }
  return files;
};

const compilerSource = resolve(packageRoot, "../../naux-lang/src");
if (existsSync(compilerSource)) {
  const registered = new Set();
  const registration = /set_(?:stateful_)?builtin\(\s*"([^"]+)"/g;
  for (const subtree of ["runtime", "stdlib"]) {
    for (const path of walkRust(join(compilerSource, subtree))) {
      const source = readFileSync(path, "utf8");
      for (const match of source.matchAll(registration)) {
        if (!match[1].startsWith("__")) registered.add(match[1]);
      }
    }
  }
  assert.deepEqual(publicBuiltins, [...registered].sort(), "compiler builtin drift");

  const lexerSource = readFileSync(join(compilerSource, "lexer.rs"), "utf8");
  const keywordBody = lexerSource.match(
    /fn keyword_or_ident[\s\S]*?\n}\n\nfn is_ident_start/
  );
  assert.ok(keywordBody, "cannot locate compiler keyword authority");
  const grammarText = JSON.stringify(grammar);
  for (const match of keywordBody[0].matchAll(/"([a-z]+)"\s*=>\s*TokenKind::/g)) {
    assert.ok(grammarText.includes(match[1]), `compiler keyword drift: ${match[1]}`);
  }

  const parserSource = readFileSync(join(compilerSource, "parser/parser.rs"), "utf8");
  const actionBody = parserSource.match(
    /fn parse_action_stmt[\s\S]*?\n    fn parse_syscall_action/
  );
  assert.ok(actionBody, "cannot locate compiler action authority");
  for (const match of actionBody[0].matchAll(/"([a-z_]+)"\s*=>/g)) {
    assert.ok(grammarText.includes(match[1]), `compiler action drift: ${match[1]}`);
  }
}

const fixture = readFileSync(join(packageRoot, "test/fixtures/syntax-tour.nx"), "utf8");
for (const fragment of ["~ fn", "I64", "$dữ_liệu", "<bytes:", "!say"]) {
  assert.ok(fixture.includes(fragment), `fixture is missing ${fragment}`);
}
assert.ok(existsSync(join(packageRoot, "LICENSE")), "standalone license missing");

console.log(
  `NAUX grammar OK: ${publicBuiltins.length} public builtins; ${identity.extensions[0]}; ${identity.tmScope}; ${identity.color}`
);
