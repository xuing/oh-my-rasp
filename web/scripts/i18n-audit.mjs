import fs from "node:fs";
import path from "node:path";
import ts from "typescript";

const root = process.cwd();
const sourceRoot = path.join(root, "src");
const failures = [];

function sourceFile(file) {
  return ts.createSourceFile(file, fs.readFileSync(file, "utf8"), ts.ScriptTarget.Latest, true, file.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
}

function location(sf, node) {
  const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return `${path.relative(root, sf.fileName)}:${line + 1}:${character + 1}`;
}

function unwrapExpression(expression) {
  let current = expression;
  while (ts.isAsExpression(current) || ts.isSatisfiesExpression?.(current) || ts.isParenthesizedExpression(current)) {
    current = current.expression;
  }
  return current;
}

function propertyNameText(name) {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)) {
    return name.text;
  }
  return undefined;
}

function readObjectLiteral(object, prefix = "") {
  const entries = new Map();
  for (const property of object.properties) {
    if (!ts.isPropertyAssignment(property)) {
      continue;
    }
    const name = propertyNameText(property.name);
    if (!name) {
      continue;
    }
    const key = prefix ? `${prefix}.${name}` : name;
    const value = unwrapExpression(property.initializer);
    if (ts.isStringLiteral(value) || ts.isNoSubstitutionTemplateLiteral(value)) {
      entries.set(key, value.text);
    } else if (ts.isObjectLiteralExpression(value)) {
      for (const [childKey, childValue] of readObjectLiteral(value, key)) {
        entries.set(childKey, childValue);
      }
    }
  }
  return entries;
}

function findConstObject(sf, name) {
  let found;
  function visit(node) {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === name && node.initializer) {
      const initializer = unwrapExpression(node.initializer);
      if (ts.isObjectLiteralExpression(initializer)) {
        found = initializer;
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(sf);
  return found;
}

function assertSameKeys(label, expected, actual) {
  const expectedKeys = [...expected.keys()].sort();
  const actualKeys = [...actual.keys()].sort();
  for (const key of expectedKeys) {
    if (!actual.has(key)) {
      failures.push(`${label} is missing translation key "${key}"`);
    } else if (!String(actual.get(key)).trim()) {
      failures.push(`${label} has an empty translation for "${key}"`);
    }
  }
  for (const key of actualKeys) {
    if (!expected.has(key)) {
      failures.push(`${label} has an extra translation key "${key}"`);
    }
  }
}

function validateUiCopy() {
  const sf = sourceFile(path.join(sourceRoot, "i18n", "copy.tsx"));
  const en = readObjectLiteral(findConstObject(sf, "en"));
  const zh = readObjectLiteral(findConstObject(sf, "zh"));
  const ja = readObjectLiteral(findConstObject(sf, "ja"));
  assertSameKeys("uiCopy.zh", en, zh);
  assertSameKeys("uiCopy.ja", en, ja);
}

function validateI18nextResources() {
  const sf = sourceFile(path.join(sourceRoot, "i18n", "resources.ts"));
  const resources = findConstObject(sf, "resources");
  if (!resources) {
    failures.push("Unable to find i18n resources object");
    return;
  }
  const localeObjects = new Map();
  for (const property of resources.properties) {
    if (!ts.isPropertyAssignment(property)) {
      continue;
    }
    const name = propertyNameText(property.name);
    const value = unwrapExpression(property.initializer);
    if (name && ts.isObjectLiteralExpression(value)) {
      localeObjects.set(name, readObjectLiteral(value));
    }
  }
  const en = localeObjects.get("en");
  if (!en) {
    failures.push("i18n resources are missing the en locale");
    return;
  }
  for (const locale of ["zh", "ja"]) {
    const entries = localeObjects.get(locale);
    if (!entries) {
      failures.push(`i18n resources are missing the ${locale} locale`);
      continue;
    }
    assertSameKeys(`resources.${locale}`, en, entries);
  }
}

function walk(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      return walk(fullPath);
    }
    return fullPath;
  });
}

const userFacingAttributes = new Set(["aria-label", "title", "placeholder", "alt", "label", "detail", "loading", "error"]);
const nonUserFacingAttributes = new Set([
  "accept",
  "autoComplete",
  "className",
  "download",
  "htmlFor",
  "id",
  "k",
  "key",
  "max",
  "method",
  "min",
  "name",
  "rel",
  "role",
  "to",
  "tone",
  "type",
  "value",
  "variant"
]);
const allowedCalls = new Set(["copy", "copyLoose", "notice", "t", "translateNotice", "translateUiCopy"]);
const noticeSetters = new Set([
  "setAlertMessage",
  "setApplicationMessage",
  "setEnvironmentMessage",
  "setError",
  "setMessage",
  "setRecycleMessage",
  "setSecretMessage",
  "setSettingMessage",
  "setStatus",
  "setUserMessage"
]);

function callName(expression) {
  if (ts.isIdentifier(expression)) {
    return expression.text;
  }
  if (ts.isPropertyAccessExpression(expression)) {
    return expression.name.text;
  }
  return "";
}

function ancestor(node, predicate) {
  let current = node.parent;
  while (current) {
    if (predicate(current)) {
      return current;
    }
    current = current.parent;
  }
  return undefined;
}

function isInImportOrType(node) {
  return Boolean(ancestor(node, current => ts.isImportDeclaration(current) || ts.isTypeNode(current) || ts.isInterfaceDeclaration(current) || ts.isTypeAliasDeclaration(current)));
}

function isInsideAllowedCall(node) {
  const call = ancestor(node, ts.isCallExpression);
  return Boolean(call && allowedCalls.has(callName(call.expression)));
}

function enclosingJsxAttribute(node) {
  return ancestor(node, ts.isJsxAttribute);
}

function isInsideNonUserFacingAttribute(node) {
  const attribute = enclosingJsxAttribute(node);
  return Boolean(attribute && nonUserFacingAttributes.has(attribute.name.getText()));
}

function hasLetters(text) {
  return /[A-Za-z]/.test(text);
}

function validateSourceFile(file) {
  const sf = sourceFile(file);
  function visit(node) {
    if (ts.isJsxText(node)) {
      const text = node.getText(sf).replace(/\s+/g, " ").trim();
      if (hasLetters(text)) {
        failures.push(`${location(sf, node)} raw JSX text "${text}" must use UiText or t()`);
      }
    }

    if (ts.isJsxAttribute(node) && node.initializer && ts.isStringLiteral(node.initializer) && userFacingAttributes.has(node.name.getText(sf))) {
      failures.push(`${location(sf, node)} user-facing attribute "${node.name.getText(sf)}" must be localized`);
    }

    if (ts.isPropertyAssignment(node) && (propertyNameText(node.name) === "status" || propertyNameText(node.name) === "error")) {
      const initializer = unwrapExpression(node.initializer);
      if ((ts.isStringLiteral(initializer) || ts.isNoSubstitutionTemplateLiteral(initializer)) && hasLetters(initializer.text)) {
        failures.push(`${location(sf, initializer)} form notice "${initializer.text}" must use notice()`);
      }
    }

    if (ts.isCallExpression(node) && noticeSetters.has(callName(node.expression))) {
      const [firstArg] = node.arguments;
      if ((ts.isStringLiteral(firstArg) || ts.isNoSubstitutionTemplateLiteral(firstArg)) && hasLetters(firstArg.text)) {
        failures.push(`${location(sf, firstArg)} notice setter string "${firstArg.text}" must use notice()`);
      }
    }

    if ((ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && hasLetters(node.text)) {
      const attribute = enclosingJsxAttribute(node);
      const inJsxExpression = Boolean(ancestor(node, ts.isJsxExpression));
      const isDisplayedBranch =
        ts.isConditionalExpression(node.parent) && (node.parent.whenTrue === node || node.parent.whenFalse === node) && inJsxExpression;
      const isDisplayedFallback =
        ts.isBinaryExpression(node.parent) &&
        [ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken, ts.SyntaxKind.PlusToken].includes(node.parent.operatorToken.kind) &&
        inJsxExpression;
      if (
        !isInImportOrType(node) &&
        !isInsideAllowedCall(node) &&
        !isInsideNonUserFacingAttribute(node) &&
        !(attribute && !userFacingAttributes.has(attribute.name.getText(sf))) &&
        (isDisplayedBranch || isDisplayedFallback)
      ) {
        failures.push(`${location(sf, node)} displayed string "${node.text}" must use UiText, UiValue, copy(), or notice()`);
      }
    }

    ts.forEachChild(node, visit);
  }
  visit(sf);
}

validateUiCopy();
validateI18nextResources();

for (const file of walk(sourceRoot)) {
  if (!/\.(tsx|ts)$/.test(file)) {
    continue;
  }
  if (file.includes(`${path.sep}test${path.sep}`) || file.endsWith(".test.ts") || file.endsWith(".test.tsx")) {
    continue;
  }
  if (file.endsWith(path.join("i18n", "copy.tsx")) || file.endsWith(path.join("i18n", "resources.ts"))) {
    continue;
  }
  validateSourceFile(file);
}

if (failures.length > 0) {
  console.error("i18n audit failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("i18n audit passed.");
