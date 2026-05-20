#!/usr/bin/env php
<?php
/**
 * extract_php_metadata.php — primary static-first source for recipe inventory.
 *
 * Token-based PHP metadata extractor. Uses token_get_all() (lexical only —
 * does NOT execute PHP code, does NOT autoload, does NOT bootstrap a kernel).
 *
 * Output: JSON on stdout. Errors/warnings on stderr.
 *
 * Usage:
 *   php extract_php_metadata.php --kind=<KIND> [--project-root=<dir>]
 *                                [--exclude=<csv>] [--max-file-size=<bytes>]
 *                                <file_or_dir>
 *
 * Kinds:
 *   class              — FQN, parent, interfaces, traits, class-level attributes
 *   symbols            — bulk: namespace + class names + kinds
 *   routes             — Symfony #[Route] attributes (multi-line, named args, methods[])
 *   forms              — *Type.php classes: data_class, csrf_protection, allow_extra_fields
 *   voters             — *Voter*.php classes: supported attributes + subjects
 *   serializer-groups  — properties/methods with #[Groups(...)]
 *   easyadmin-crud     — classes extending AbstractCrudController:
 *                        entity_fqcn, configure_fields[{name, field_type, modifiers[]}],
 *                        configure_actions.disabled[], page_titles{}
 *   sonata-admin       — classes extending Sonata\AdminBundle\Admin\AbstractAdmin:
 *                        entity_fqcn (from getClass() return), form_fields[]
 *                        (names from configureFormFields), unresolved_fields
 *
 * --exclude:        csv of relative-to-project-root path prefixes that are
 *                   skipped *before* parsing (whole subtree is not traversed,
 *                   so vendor/, var/cache/, node_modules/ never hit token_get_all).
 *                   When the flag is absent, a built-in default kicks in
 *                   (see DEFAULT_EXCLUDE below). Keep DEFAULT_EXCLUDE in sync
 *                   with sandbox.py:DEFAULT_EXCLUDE.
 * --max-file-size:  per-file byte cap; oversize files are skipped with a
 *                   stderr warning. Defaults to 2 MiB. Protects against
 *                   auto-generated giants (e.g. vimeo/psalm CallMap_*.php)
 *                   that bust memory_limit.
 *
 * Exit codes: 0 ok, 2 usage error, 1 internal failure.
 */

declare(strict_types=1);

if (PHP_VERSION_ID < 80000) {
    fwrite(STDERR, "PHP 8.0+ required (got " . PHP_VERSION . ")\n");
    exit(2);
}

// Polyfills for tokens that may not exist on this minor version.
if (!defined('T_READONLY')) { define('T_READONLY', -1001); }
if (!defined('T_ENUM')) { define('T_ENUM', -1002); }
if (!defined('T_NAME_QUALIFIED')) { define('T_NAME_QUALIFIED', -1003); }
if (!defined('T_NAME_FULLY_QUALIFIED')) { define('T_NAME_FULLY_QUALIFIED', -1004); }
if (!defined('T_NAME_RELATIVE')) { define('T_NAME_RELATIVE', -1005); }
if (!defined('T_ATTRIBUTE')) { define('T_ATTRIBUTE', -1006); }

// ---------------------------------------------------------------------------
// CLI args.
// ---------------------------------------------------------------------------

// Built-in fallback exclude prefixes. Used only when caller did not pass
// --exclude= explicitly (e.g. ad-hoc manual run). Production callers
// (sandbox.py) always pass an explicit list = DEFAULT_EXCLUDE ∪ user-extra.
// Keep this list aligned with bin/recon/sandbox.py:DEFAULT_EXCLUDE.
const DEFAULT_EXCLUDE = [
    'vendor', 'var/cache', 'var/log', 'node_modules',
    'storage/framework/cache', 'storage/logs', 'bootstrap/cache',
    'public/build', '.git',
];
const DEFAULT_MAX_FILE_SIZE = 2097152; // 2 MiB

$kind = null;
$path = null;
$projectRootArg = null;
$excludeArg = null;       // null → use DEFAULT_EXCLUDE; "" → no exclude at all
$maxFileSize = DEFAULT_MAX_FILE_SIZE;
foreach (array_slice($_SERVER['argv'], 1) as $a) {
    if (str_starts_with($a, '--kind=')) {
        $kind = substr($a, 7);
    } elseif (str_starts_with($a, '--project-root=')) {
        $projectRootArg = substr($a, 15);
    } elseif (str_starts_with($a, '--exclude=')) {
        $excludeArg = substr($a, 10);
    } elseif (str_starts_with($a, '--max-file-size=')) {
        $raw = substr($a, 16);
        if (!ctype_digit($raw)) {
            fwrite(STDERR, "--max-file-size must be a non-negative integer (got: $raw)\n");
            exit(2);
        }
        $maxFileSize = (int)$raw;
    } elseif (!str_starts_with($a, '--') && $path === null) {
        $path = $a;
    }
}
if ($kind === null || $path === null) {
    fwrite(STDERR, "usage: php extract_php_metadata.php --kind=<KIND> [--project-root=<dir>] "
        . "[--exclude=<csv>] [--max-file-size=<bytes>] <file_or_dir>\n");
    exit(2);
}

$excludePrefixes = [];
$excludeSource = $excludeArg === null ? DEFAULT_EXCLUDE : explode(',', $excludeArg);
foreach ($excludeSource as $p) {
    $p = trim($p);
    $p = trim($p, '/');
    if ($p === '') continue;
    $excludePrefixes[] = $p . '/';
}
if (!file_exists($path)) {
    fwrite(STDERR, "path not found: $path\n");
    exit(2);
}
$realPath = realpath($path);
if ($realPath === false) {
    fwrite(STDERR, "could not resolve realpath: $path\n");
    exit(2);
}

// Project root for symlink-escape protection (C1): every collected file must
// resolve under this root. Default: target itself (or its parent for single files).
if ($projectRootArg !== null) {
    $projectRoot = realpath($projectRootArg);
    if ($projectRoot === false) {
        fwrite(STDERR, "--project-root not found: $projectRootArg\n");
        exit(2);
    }
} else {
    $projectRoot = is_dir($realPath) ? $realPath : dirname($realPath);
}
$projectRootPrefix = rtrim($projectRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;

// ---------------------------------------------------------------------------
// Collect PHP files.
// ---------------------------------------------------------------------------

/** Returns true if $candidate (after realpath) lies inside $projectRoot. */
function pathInsideRoot(string $candidate, string $projectRoot, string $projectRootPrefix): bool {
    $real = realpath($candidate);
    if ($real === false) return false;
    return $real === $projectRoot || str_starts_with($real, $projectRootPrefix);
}

/**
 * Compute path of $abs relative to $projectRoot using $projectRootPrefix
 * (which already has the trailing separator). Returns "" if $abs is the
 * project root itself or outside it.
 */
function relativeToProjectRoot(string $abs, string $projectRoot, string $projectRootPrefix): string {
    if ($abs === $projectRoot) return '';
    if (!str_starts_with($abs, $projectRootPrefix)) return '';
    return substr($abs, strlen($projectRootPrefix));
}

$files = [];
if (is_file($realPath)) {
    if (pathInsideRoot($realPath, $projectRoot, $projectRootPrefix)) {
        // Single-file invocation respects --max-file-size (cheap safety net),
        // but ignores --exclude (caller asked for *this* file explicitly).
        $sz = @filesize($realPath);
        if ($maxFileSize > 0 && $sz !== false && $sz > $maxFileSize) {
            fwrite(STDERR, "warn: skipping $realPath: file size $sz exceeds --max-file-size=$maxFileSize\n");
        } else {
            $files = [$realPath];
        }
    } else {
        fwrite(STDERR, "warn: target $realPath outside project root $projectRoot — skipped\n");
    }
} else {
    // RecursiveCallbackFilterIterator wraps the directory iterator so excluded
    // subtrees (vendor/, var/cache/, …) are NEVER descended into — extractor
    // does not even open files in those directories. Oversize files are
    // skipped at file-level with a stderr warning.
    $rdi = new RecursiveDirectoryIterator($realPath, FilesystemIterator::SKIP_DOTS);
    $filter = new RecursiveCallbackFilterIterator(
        $rdi,
        function ($current, $key, $iterator) use ($excludePrefixes, $projectRoot, $projectRootPrefix, $maxFileSize) {
            $abs = $current->getPathname();
            $rel = relativeToProjectRoot($abs, $projectRoot, $projectRootPrefix);
            if ($rel !== '') {
                $relWithSlash = $rel . '/';
                foreach ($excludePrefixes as $prefix) {
                    if (str_starts_with($relWithSlash, $prefix)) {
                        return false;
                    }
                }
            }
            // File-size cap (file-level only; directories pass through).
            if ($current->isFile() && $maxFileSize > 0) {
                $sz = $current->getSize();
                if ($sz !== false && $sz > $maxFileSize) {
                    fwrite(STDERR, "warn: skipping $rel: file size $sz exceeds --max-file-size=$maxFileSize\n");
                    return false;
                }
            }
            return true;
        }
    );
    // SKIP_DOTS only; symlinks are followed by RecursiveDirectoryIterator (PHP default),
    // so we sanitize each file via realpath()-vs-projectRoot below.
    $rii = new RecursiveIteratorIterator($filter);
    foreach ($rii as $f) {
        if (!$f->isFile() || $f->getExtension() !== 'php') continue;
        $abs = $f->getPathname();
        if (!pathInsideRoot($abs, $projectRoot, $projectRootPrefix)) {
            fwrite(STDERR, "warn: skipping symlink outside project: $abs\n");
            continue;
        }
        // Use the realpath form so downstream `file` fields are normalized.
        $real = realpath($abs);
        if ($real !== false) $files[] = $real;
    }
    sort($files);
    $files = array_values(array_unique($files));
}

// ---------------------------------------------------------------------------
// Parse each file.
// ---------------------------------------------------------------------------

// M4: kind-aware body collection — only forms/voters/easyadmin-crud need method body text.
$collectBodies = in_array($kind, ['forms', 'voters', 'easyadmin-crud', 'sonata-admin'], true);
$parsed = [];
foreach ($files as $f) {
    try {
        $parsed[$f] = parseFile($f, $collectBodies);
    } catch (\Throwable $e) {
        fwrite(STDERR, "warn: failed to parse $f: " . $e->getMessage() . "\n");
    }
}

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

switch ($kind) {
    case 'class':             $result = collectClasses($parsed); break;
    case 'symbols':           $result = collectSymbols($parsed); break;
    case 'routes':            $result = collectRoutes($parsed); break;
    case 'forms':             $result = collectForms($parsed); break;
    case 'voters':            $result = collectVoters($parsed); break;
    case 'serializer-groups': $result = collectGroups($parsed); break;
    case 'easyadmin-crud':    $result = collectEasyadminCrud($parsed); break;
    case 'sonata-admin':      $result = collectSonataAdmin($parsed); break;
    default:
        fwrite(STDERR, "unknown kind: $kind\n");
        exit(2);
}

// JSON_INVALID_UTF8_SUBSTITUTE (H2): replace invalid UTF-8 with U+FFFD instead of
// silently returning false → empty stdout → swallowed file.
$encoded = json_encode(
    $result,
    JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE,
);
if ($encoded === false) {
    fwrite(STDERR, "json_encode failed: " . json_last_error_msg() . "\n");
    exit(1);
}
echo $encoded . "\n";
exit(0);


// ===========================================================================
// Token stream.
// ===========================================================================

function tokenize(string $code): array {
    $raw = @token_get_all($code);
    if ($raw === false) return [];
    $out = [];
    foreach ($raw as $t) {
        if (is_array($t)) {
            $out[] = ['id' => $t[0], 'text' => $t[1], 'line' => $t[2]];
        } else {
            $out[] = ['id' => 0, 'text' => $t, 'line' => 0];
        }
    }
    return $out;
}

function isTrivia(array $tok): bool {
    return $tok['id'] === T_WHITESPACE || $tok['id'] === T_COMMENT || $tok['id'] === T_DOC_COMMENT;
}

function skipTrivia(array $tokens, int $pos): int {
    $n = count($tokens);
    while ($pos < $n && isTrivia($tokens[$pos])) $pos++;
    return $pos;
}

function isNamePart(array $tok): bool {
    return $tok['id'] === T_STRING
        || $tok['id'] === T_NAME_QUALIFIED
        || $tok['id'] === T_NAME_FULLY_QUALIFIED
        || $tok['id'] === T_NAME_RELATIVE
        || $tok['id'] === T_NS_SEPARATOR;
}

function consumeName(array $tokens, int &$pos): string {
    $n = count($tokens);
    $name = '';
    while ($pos < $n && isNamePart($tokens[$pos])) {
        $name .= $tokens[$pos]['text'];
        $pos++;
    }
    // Normalize: in `use Foo\Bar\Baz` PHP emits `T_STRING Foo`, `T_NS_SEPARATOR \`,
    // `T_NAME_FULLY_QUALIFIED \Bar`, `T_NS_SEPARATOR \`, `T_NAME_FULLY_QUALIFIED \Baz`
    // — concatenation produces `Foo\\Bar\\Baz` (doubled separators). Collapse
    // consecutive backslashes to a single one for stable FQN strings.
    return preg_replace('/\\\\+/', '\\', $name) ?? $name;
}

function lastNamePart(string $fqn): string {
    $parts = explode('\\', $fqn);
    return end($parts);
}

function resolveName(string $name, ?string $namespace, array $uses): string {
    if (str_starts_with($name, '\\')) return ltrim($name, '\\');
    $parts = explode('\\', $name);
    $first = $parts[0];
    if (isset($uses[$first])) {
        $rest = array_slice($parts, 1);
        return $uses[$first] . (empty($rest) ? '' : '\\' . implode('\\', $rest));
    }
    return $namespace ? $namespace . '\\' . $name : $name;
}

/**
 * Build map `class_fqn → resolved_parent_fqn` across all parsed files.
 * Project-local base classes (e.g. BaseCrudController) appear here; vendor
 * parents do not, so transitive lookups bottom out cleanly when reaching
 * a parent the parser never saw.
 */
function buildClassParentMap(array $parsed): array {
    $map = [];
    foreach ($parsed as $f) {
        foreach ($f['classes'] as $cls) {
            $fqn = $cls['fqn'] ?? null;
            if (!$fqn) continue;
            $map[$fqn] = $cls['extends'] ?? null;
        }
    }
    return $map;
}

/**
 * Return true if any ancestor of $startFqn (within $maxDepth hops) has its
 * fully-qualified parent name listed in $targetFqns. FQN-first prevents
 * collisions with project-local classes that happen to share a short name
 * with a Symfony / Sonata / EasyAdmin base (`App\Framework\AbstractAdmin`
 * is NOT a Sonata admin).
 *
 * The first hop (direct parent) is checked too — callers can use this in
 * place of `$cls['extends'] === $target`.
 */
function inheritsFromFqns(string $startFqn, array $targetFqns, array $parentMap, int $maxDepth = 5): bool {
    $current = $startFqn;
    $depth = 0;
    $seen = [];
    while ($current !== null && $depth < $maxDepth) {
        if (isset($seen[$current])) return false; // cycle guard
        $seen[$current] = true;
        $parent = $parentMap[$current] ?? null;
        if ($parent === null) return false;
        if (in_array($parent, $targetFqns, true)) {
            return true;
        }
        $current = $parent;
        $depth++;
    }
    return false;
}

function skipBalanced(array $tokens, int $pos, string $open, string $close): int {
    $n = count($tokens);
    if ($pos >= $n || !($tokens[$pos]['id'] === 0 && $tokens[$pos]['text'] === $open)) return $pos;
    $depth = 1;
    $pos++;
    while ($pos < $n && $depth > 0) {
        $t = $tokens[$pos];
        if ($t['id'] === 0) {
            if ($t['text'] === $open) $depth++;
            elseif ($t['text'] === $close) $depth--;
        }
        $pos++;
    }
    return $pos;
}


// ===========================================================================
// File parser.
// ===========================================================================

function parseFile(string $path, bool $collectBodies = false): array {
    $code = @file_get_contents($path);
    if ($code === false) throw new \RuntimeException("cannot read $path");
    $tokens = tokenize($code);
    $n = count($tokens);

    $namespace = null;
    $uses = [];      // short_name => FQN
    $classes = [];

    $pos = 0;
    $pendingAttrs = [];
    $pendingClassMods = [];

    while ($pos < $n) {
        $pos = skipTrivia($tokens, $pos);
        if ($pos >= $n) break;
        $t = $tokens[$pos];

        if ($t['id'] === T_NAMESPACE) {
            [$namespace, $pos] = parseNamespaceDecl($tokens, $pos + 1);
            continue;
        }
        if ($t['id'] === T_USE) {
            $pos = parseUseDecl($tokens, $pos + 1, $uses);
            continue;
        }
        if ($t['id'] === T_ATTRIBUTE) {
            [$attrs, $pos] = parseAttributeGroup($tokens, $pos);
            $pendingAttrs = array_merge($pendingAttrs, $attrs);
            continue;
        }
        if ($t['id'] === T_FINAL || $t['id'] === T_ABSTRACT || $t['id'] === T_READONLY) {
            // L5: peek past further modifiers — if no class-keyword follows,
            // drop pendingAttrs to prevent attribute leakage to a later
            // top-level construct in malformed/partial files.
            $peek = skipTrivia($tokens, $pos + 1);
            while ($peek < $n && in_array($tokens[$peek]['id'], [T_FINAL, T_ABSTRACT, T_READONLY], true)) {
                $peek = skipTrivia($tokens, $peek + 1);
            }
            $followsClass = $peek < $n && in_array(
                $tokens[$peek]['id'],
                [T_CLASS, T_INTERFACE, T_TRAIT, T_ENUM],
                true
            );
            if (!$followsClass) {
                $pendingAttrs = [];
                $pendingClassMods = [];
            } else {
                $pendingClassMods[] = $t['id'];
            }
            $pos++;
            continue;
        }
        if ($t['id'] === T_CLASS || $t['id'] === T_INTERFACE || $t['id'] === T_TRAIT || $t['id'] === T_ENUM) {
            // H3: anonymous class (`new class { ... }`) has no name token after T_CLASS.
            // It's an expression, not a top-level declaration — skip its body and drop attrs.
            $peek = skipTrivia($tokens, $pos + 1);
            // Anonymous class may have constructor args: `new class($a) {}` — '(' before '{'.
            if ($peek < $n && $tokens[$peek]['id'] !== T_STRING) {
                // Skip until '{' then balance.
                while ($peek < $n && !($tokens[$peek]['id'] === 0 && $tokens[$peek]['text'] === '{')) $peek++;
                if ($peek < $n) {
                    $pos = skipBalanced($tokens, $peek, '{', '}');
                } else {
                    $pos++;
                }
                $pendingAttrs = [];
                $pendingClassMods = [];
                continue;
            }
            $isAbstract = in_array(T_ABSTRACT, $pendingClassMods, true);
            [$cls, $pos] = parseClass($tokens, $pos, $t['id'], $namespace, $uses, $pendingAttrs, $collectBodies, $isAbstract);
            $classes[] = $cls;
            $pendingAttrs = [];
            $pendingClassMods = [];
            continue;
        }
        if ($t['id'] === T_FUNCTION) {
            $pos = skipFunction($tokens, $pos);
            $pendingAttrs = [];
            continue;
        }
        $pos++;
    }

    // H1: post-process — resolve FQN for ClassName::class / ClassName::CONST values
    // collected during attribute parsing (parser had no namespace/uses context yet).
    foreach ($classes as &$cls) {
        $cls['attributes'] = resolveAttrValueClassNames($cls['attributes'], $namespace, $uses);
        foreach ($cls['methods'] as &$m) {
            $m['attributes'] = resolveAttrValueClassNames($m['attributes'], $namespace, $uses);
        }
        unset($m);
        foreach ($cls['properties'] as &$p) {
            $p['attributes'] = resolveAttrValueClassNames($p['attributes'], $namespace, $uses);
        }
        unset($p);
    }
    unset($cls);

    return [
        'path' => $path,
        'namespace' => $namespace,
        'uses' => $uses,
        'classes' => $classes,
    ];
}

/** Walk attribute names and arguments to resolve class names against namespace/use clauses. */
function resolveAttrValueClassNames(array $attrs, ?string $namespace, array $uses): array {
    foreach ($attrs as &$a) {
        // Resolve attribute name itself (e.g. `#[Entity]` with `use Doctrine\ORM\Mapping\{Entity}` → FQN).
        if (isset($a['name']) && is_string($a['name'])) {
            $a['name'] = ltrim(resolveName($a['name'], $namespace, $uses), '\\');
        }
        if (!isset($a['arguments'])) continue;
        foreach (['positional', 'named'] as $bucket) {
            if (!isset($a['arguments'][$bucket])) continue;
            foreach ($a['arguments'][$bucket] as $k => $v) {
                $a['arguments'][$bucket][$k] = resolveValueClassNames($v, $namespace, $uses);
            }
        }
    }
    unset($a);
    return $attrs;
}

function resolveValueClassNames(array $v, ?string $namespace, array $uses): array {
    $type = $v['type'] ?? null;
    if ($type === 'class_const' || $type === 'const_ref') {
        $left = $v['value'] ?? '';
        if (is_string($left) && $left !== '' && !str_contains($left, '::')) {
            // Skip self/static/parent — they cannot be resolved without class context.
            $low = strtolower($left);
            if (!in_array($low, ['self', 'static', 'parent'], true)) {
                $v['value'] = resolveName($left, $namespace, $uses);
            }
        }
    } elseif ($type === 'array' && isset($v['value']) && is_array($v['value'])) {
        foreach ($v['value'] as $k => $item) {
            if (isset($item['key']) && is_array($item['key'])) {
                $v['value'][$k]['key'] = resolveValueClassNames($item['key'], $namespace, $uses);
            }
            if (isset($item['value']) && is_array($item['value'])) {
                $v['value'][$k]['value'] = resolveValueClassNames($item['value'], $namespace, $uses);
            }
        }
    }
    return $v;
}

/** @return array{0: ?string, 1: int} */
function parseNamespaceDecl(array $tokens, int $pos): array {
    $n = count($tokens);
    $pos = skipTrivia($tokens, $pos);
    $name = consumeName($tokens, $pos);
    while ($pos < $n && !($tokens[$pos]['id'] === 0 && ($tokens[$pos]['text'] === ';' || $tokens[$pos]['text'] === '{'))) {
        $pos++;
    }
    if ($pos < $n) $pos++;
    return [$name === '' ? null : $name, $pos];
}

function parseUseDecl(array $tokens, int $pos, array &$uses): int {
    $n = count($tokens);
    $pos = skipTrivia($tokens, $pos);
    if ($pos < $n && ($tokens[$pos]['id'] === T_FUNCTION || $tokens[$pos]['id'] === T_CONST)) {
        // Skip use function/const X — we don't track these.
        while ($pos < $n && !($tokens[$pos]['id'] === 0 && $tokens[$pos]['text'] === ';')) $pos++;
        if ($pos < $n) $pos++;
        return $pos;
    }
    while ($pos < $n) {
        $pos = skipTrivia($tokens, $pos);
        $name = consumeName($tokens, $pos);
        if ($name === '') break;
        // Group use: `Foo\{Bar, Baz}` — handle minimal.
        $pos = skipTrivia($tokens, $pos);
        if ($pos < $n && $tokens[$pos]['id'] === 0 && $tokens[$pos]['text'] === '{') {
            // Group use. Trim trailing backslash from prefix.
            $prefix = rtrim($name, '\\');
            $pos++; // skip '{'
            while ($pos < $n) {
                $pos = skipTrivia($tokens, $pos);
                if ($pos < $n && $tokens[$pos]['id'] === 0 && $tokens[$pos]['text'] === '}') { $pos++; break; }
                $sub = consumeName($tokens, $pos);
                $alias = null;
                $pos = skipTrivia($tokens, $pos);
                if ($pos < $n && $tokens[$pos]['id'] === T_AS) {
                    $pos = skipTrivia($tokens, $pos + 1);
                    if ($pos < $n && $tokens[$pos]['id'] === T_STRING) {
                        $alias = $tokens[$pos]['text'];
                        $pos++;
                    }
                }
                if ($sub !== '') {
                    $full = $prefix . '\\' . ltrim($sub, '\\');
                    $short = $alias ?? lastNamePart($sub);
                    $uses[$short] = ltrim($full, '\\');
                }
                $pos = skipTrivia($tokens, $pos);
                if ($pos < $n && $tokens[$pos]['id'] === 0 && $tokens[$pos]['text'] === ',') { $pos++; continue; }
                if ($pos < $n && $tokens[$pos]['id'] === 0 && $tokens[$pos]['text'] === '}') { $pos++; break; }
            }
            break;
        }
        $alias = null;
        if ($pos < $n && $tokens[$pos]['id'] === T_AS) {
            $pos = skipTrivia($tokens, $pos + 1);
            if ($pos < $n && $tokens[$pos]['id'] === T_STRING) {
                $alias = $tokens[$pos]['text'];
                $pos++;
            }
        }
        $short = $alias ?? lastNamePart($name);
        $uses[$short] = ltrim($name, '\\');
        $pos = skipTrivia($tokens, $pos);
        if ($pos < $n && $tokens[$pos]['id'] === 0 && $tokens[$pos]['text'] === ',') { $pos++; continue; }
        break;
    }
    while ($pos < $n && !($tokens[$pos]['id'] === 0 && $tokens[$pos]['text'] === ';')) $pos++;
    if ($pos < $n) $pos++;
    return $pos;
}

function skipFunction(array $tokens, int $pos): int {
    $n = count($tokens);
    while ($pos < $n) {
        $t = $tokens[$pos];
        if ($t['id'] === 0 && $t['text'] === '{') return skipBalanced($tokens, $pos, '{', '}');
        if ($t['id'] === 0 && $t['text'] === ';') return $pos + 1;
        $pos++;
    }
    return $pos;
}


// ===========================================================================
// Attribute parser.
// ===========================================================================

/** @return array{0: array, 1: int} */
function parseAttributeGroup(array $tokens, int $pos): array {
    // tokens[$pos]['id'] === T_ATTRIBUTE; text = '#['.
    $n = count($tokens);
    $line = $tokens[$pos]['line'] ?? 0;
    $pos++;
    $depth = 1; // we are inside `[`
    $attrs = [];

    while ($pos < $n && $depth > 0) {
        $pos = skipTrivia($tokens, $pos);
        if ($pos >= $n) break;
        $t = $tokens[$pos];
        if ($t['id'] === 0 && $t['text'] === ']') {
            $depth--;
            $pos++;
            if ($depth === 0) break;
            continue;
        }
        $name = consumeName($tokens, $pos);
        if ($name === '') {
            $pos++;
            continue;
        }
        $pos = skipTrivia($tokens, $pos);
        $args = ['positional' => [], 'named' => []];
        if ($pos < $n && $tokens[$pos]['id'] === 0 && $tokens[$pos]['text'] === '(') {
            [$args, $pos] = parseAttributeArgs($tokens, $pos);
        }
        $attrs[] = ['name' => $name, 'arguments' => $args, 'line' => $line];
        $pos = skipTrivia($tokens, $pos);
        if ($pos < $n && $tokens[$pos]['id'] === 0 && $tokens[$pos]['text'] === ',') {
            $pos++;
            continue;
        }
    }
    return [$attrs, $pos];
}

/** @return array{0: array{positional: list, named: array}, 1: int} */
function parseAttributeArgs(array $tokens, int $pos): array {
    $n = count($tokens);
    $pos++; // skip '('
    $depth = 1;
    $segments = [];
    $current = [];

    while ($pos < $n && $depth > 0) {
        $t = $tokens[$pos];
        if ($t['id'] === 0) {
            if ($t['text'] === '(' || $t['text'] === '[' || $t['text'] === '{') {
                $depth++;
                $current[] = $t;
                $pos++;
                continue;
            }
            if ($t['text'] === ')' || $t['text'] === ']' || $t['text'] === '}') {
                $depth--;
                if ($depth === 0) {
                    if (!empty($current) || !empty($segments)) {
                        $segments[] = $current;
                    }
                    $pos++;
                    break;
                }
                $current[] = $t;
                $pos++;
                continue;
            }
            if ($t['text'] === ',' && $depth === 1) {
                $segments[] = $current;
                $current = [];
                $pos++;
                continue;
            }
        }
        $current[] = $t;
        $pos++;
    }

    $args = ['positional' => [], 'named' => []];
    foreach ($segments as $seg) {
        $clean = array_values(array_filter($seg, fn($t) => !isTrivia($t)));
        if (empty($clean)) continue;
        // Named arg detection: <identifier> ':' <value>.
        // Identifier may be a PHP reserved word (e.g. `class`, `function`) — any
        // token whose text matches a valid PHP identifier counts.
        if (count($clean) >= 2
            && is_string($clean[0]['text'])
            && preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $clean[0]['text'])
            && $clean[1]['id'] === 0
            && $clean[1]['text'] === ':'
            // Don't confuse with `Foo::class`: T_DOUBLE_COLON is "::", a single token,
            // never appearing here as `:` followed by `:`.
        ) {
            $name = $clean[0]['text'];
            $rest = array_slice($clean, 2);
            $args['named'][$name] = parseValueTokens($rest);
        } else {
            $args['positional'][] = parseValueTokens($clean);
        }
    }
    return [$args, $pos];
}


// ===========================================================================
// Value parser (limited: scalar / array / class_const / expr fallback).
// ===========================================================================

function parseValueTokens(array $tokens): array {
    $tokens = array_values(array_filter($tokens, fn($t) => !isTrivia($t)));
    if (empty($tokens)) return ['type' => 'null', 'value' => null, 'raw' => ''];
    $raw = implode('', array_map(fn($t) => $t['text'], $tokens));

    if (count($tokens) === 1) {
        $t = $tokens[0];
        if ($t['id'] === T_CONSTANT_ENCAPSED_STRING) {
            return ['type' => 'string', 'value' => stripQuotes($t['text']), 'raw' => $raw];
        }
        if ($t['id'] === T_LNUMBER) return ['type' => 'int', 'value' => (int)$t['text'], 'raw' => $raw];
        if ($t['id'] === T_DNUMBER) return ['type' => 'float', 'value' => (float)$t['text'], 'raw' => $raw];
        if ($t['id'] === T_STRING) {
            $low = strtolower($t['text']);
            if ($low === 'true')  return ['type' => 'bool', 'value' => true, 'raw' => $raw];
            if ($low === 'false') return ['type' => 'bool', 'value' => false, 'raw' => $raw];
            if ($low === 'null')  return ['type' => 'null', 'value' => null, 'raw' => $raw];
            return ['type' => 'const', 'value' => $t['text'], 'raw' => $raw];
        }
    }

    // ClassName::CONST or ClassName::class — recognize via T_DOUBLE_COLON.
    foreach ($tokens as $t) {
        if ($t['id'] === T_DOUBLE_COLON) {
            // Take left side (name parts) and right side (T_STRING or T_CLASS).
            $left = '';
            $right = '';
            $sawColon = false;
            foreach ($tokens as $tt) {
                if (!$sawColon) {
                    if ($tt['id'] === T_DOUBLE_COLON) { $sawColon = true; continue; }
                    $left .= $tt['text'];
                } else {
                    $right .= $tt['text'];
                }
            }
            $type = strtolower(trim($right)) === 'class' ? 'class_const' : 'const_ref';
            return ['type' => $type, 'value' => trim($left), 'member' => trim($right), 'raw' => $raw];
        }
    }

    // Array literal: [...].
    if ($tokens[0]['id'] === 0 && $tokens[0]['text'] === '[') {
        return ['type' => 'array', 'value' => parseArrayItems($tokens, 0, '[', ']'), 'raw' => $raw];
    }
    if ($tokens[0]['id'] === T_ARRAY) {
        // array(...) — skip T_ARRAY then parse '(' '...' ')'.
        $start = 1;
        while ($start < count($tokens) && (isTrivia($tokens[$start]) || !($tokens[$start]['id'] === 0 && $tokens[$start]['text'] === '('))) $start++;
        if ($start < count($tokens)) {
            return ['type' => 'array', 'value' => parseArrayItems($tokens, $start, '(', ')'), 'raw' => $raw];
        }
    }

    return ['type' => 'expr', 'value' => $raw, 'raw' => $raw];
}

function parseArrayItems(array $tokens, int $start, string $open, string $close): array {
    $n = count($tokens);
    if ($start >= $n || !($tokens[$start]['id'] === 0 && $tokens[$start]['text'] === $open)) return [];
    $depth = 1;
    $current = [];
    $items = [];
    for ($i = $start + 1; $i < $n; $i++) {
        $t = $tokens[$i];
        if ($t['id'] === 0) {
            if ($t['text'] === '(' || $t['text'] === '[' || $t['text'] === '{') {
                $depth++; $current[] = $t; continue;
            }
            if ($t['text'] === ')' || $t['text'] === ']' || $t['text'] === '}') {
                $depth--;
                if ($depth === 0) {
                    if (!empty($current)) $items[] = parseArrayItem($current);
                    break;
                }
                $current[] = $t; continue;
            }
            if ($t['text'] === ',' && $depth === 1) {
                if (!empty($current)) $items[] = parseArrayItem($current);
                $current = [];
                continue;
            }
        }
        $current[] = $t;
    }
    return $items;
}

function parseArrayItem(array $tokens): array {
    $depth = 0;
    $arrowPos = -1;
    foreach ($tokens as $i => $t) {
        if ($t['id'] === 0) {
            if ($t['text'] === '(' || $t['text'] === '[' || $t['text'] === '{') $depth++;
            elseif ($t['text'] === ')' || $t['text'] === ']' || $t['text'] === '}') $depth--;
        }
        if ($depth === 0 && $t['id'] === T_DOUBLE_ARROW) { $arrowPos = $i; break; }
    }
    if ($arrowPos === -1) {
        return ['key' => null, 'value' => parseValueTokens($tokens)];
    }
    $keyT = array_slice($tokens, 0, $arrowPos);
    $valT = array_slice($tokens, $arrowPos + 1);
    return ['key' => parseValueTokens($keyT), 'value' => parseValueTokens($valT)];
}

function stripQuotes(string $s): string {
    if (strlen($s) < 2) return $s;
    $first = $s[0];
    if ($first !== '"' && $first !== "'") return $s;
    $inner = substr($s, 1, -1);
    if ($first === "'") {
        return strtr($inner, ["\\'" => "'", "\\\\" => "\\"]);
    }
    // Double-quoted: handle PHP escape sequences including \u{...} (H7) and \xNN.
    // For unknown escapes PHP keeps the literal backslash + char (e.g. "\g" → \g).
    $result = preg_replace_callback(
        '/\\\\(?:u\{([0-9A-Fa-f]+)\}|x([0-9A-Fa-f]{1,2})|([0-7]{1,3})|(.))/s',
        function ($m) {
            if (isset($m[1]) && $m[1] !== '') {
                $cp = intval($m[1], 16);
                return mb_chr($cp, 'UTF-8') ?: '';
            }
            if (isset($m[2]) && $m[2] !== '') {
                return chr(intval($m[2], 16));
            }
            if (isset($m[3]) && $m[3] !== '') {
                return chr(intval($m[3], 8));
            }
            $c = $m[4] ?? '';
            return match ($c) {
                'n' => "\n", 'r' => "\r", 't' => "\t",
                'v' => "\v", 'f' => "\f", 'e' => "\x1b",
                '"' => '"', '\\' => '\\', '$' => '$',
                default => '\\' . $c,
            };
        },
        $inner,
    );
    return $result ?? $inner;
}


// ===========================================================================
// Class parser.
// ===========================================================================

const CLASS_KIND_MAP = [];

function classKindOf(int $tokenId): string {
    if ($tokenId === T_CLASS) return 'class';
    if ($tokenId === T_INTERFACE) return 'interface';
    if ($tokenId === T_TRAIT) return 'trait';
    if ($tokenId === T_ENUM) return 'enum';
    return 'class';
}

function parseClass(array $tokens, int $pos, int $kindToken, ?string $namespace, array $uses, array $attrs, bool $collectBodies = false, bool $isAbstract = false): array {
    $n = count($tokens);
    $kind = classKindOf($kindToken);
    $pos++; // skip class/interface/trait/enum
    $pos = skipTrivia($tokens, $pos);
    if ($pos >= $n || $tokens[$pos]['id'] !== T_STRING) {
        return [['name' => '', 'fqn' => '', 'kind' => $kind, 'attributes' => $attrs,
                 'extends' => null, 'implements' => [], 'methods' => [], 'properties' => [],
                 'constants' => [], 'traits_used' => [], 'line' => 0,
                 'is_abstract' => $isAbstract], $pos];
    }
    $name = $tokens[$pos]['text'];
    $line = $tokens[$pos]['line'];
    $pos++;
    $pos = skipTrivia($tokens, $pos);

    // For enum: optional `: BackedType` (skip).
    if ($kind === 'enum' && $pos < $n && $tokens[$pos]['id'] === 0 && $tokens[$pos]['text'] === ':') {
        $pos++;
        $pos = skipTrivia($tokens, $pos);
        consumeName($tokens, $pos);
        $pos = skipTrivia($tokens, $pos);
    }

    $extends = null;
    $implements = [];

    if ($pos < $n && $tokens[$pos]['id'] === T_EXTENDS) {
        $pos++;
        while ($pos < $n) {
            $pos = skipTrivia($tokens, $pos);
            $tname = consumeName($tokens, $pos);
            if ($tname !== '') {
                if ($extends === null && $kind === 'class') {
                    $extends = resolveName($tname, $namespace, $uses);
                } else {
                    // Interface can extend multiple.
                    $implements[] = resolveName($tname, $namespace, $uses);
                }
            }
            $pos = skipTrivia($tokens, $pos);
            if ($pos < $n && $tokens[$pos]['id'] === 0 && $tokens[$pos]['text'] === ',') {
                $pos++; continue;
            }
            break;
        }
    }
    if ($pos < $n && $tokens[$pos]['id'] === T_IMPLEMENTS) {
        $pos++;
        while ($pos < $n) {
            $pos = skipTrivia($tokens, $pos);
            $iname = consumeName($tokens, $pos);
            if ($iname !== '') $implements[] = resolveName($iname, $namespace, $uses);
            $pos = skipTrivia($tokens, $pos);
            if ($pos < $n && $tokens[$pos]['id'] === 0 && $tokens[$pos]['text'] === ',') {
                $pos++; continue;
            }
            break;
        }
    }

    $pos = skipTrivia($tokens, $pos);
    $body = ['methods' => [], 'properties' => [], 'constants' => [], 'traits_used' => []];
    if ($pos < $n && $tokens[$pos]['id'] === 0 && $tokens[$pos]['text'] === '{') {
        [$body, $pos] = parseClassBody($tokens, $pos, $namespace, $uses, $collectBodies);
    }

    $fqn = $namespace ? $namespace . '\\' . $name : $name;
    return [[
        'name' => $name,
        'fqn' => $fqn,
        'kind' => $kind,
        'is_abstract' => $isAbstract,
        'extends' => $extends,
        'implements' => $implements,
        'attributes' => $attrs,
        'line' => $line,
        'methods' => $body['methods'],
        'properties' => $body['properties'],
        'constants' => $body['constants'],
        'traits_used' => $body['traits_used'],
    ], $pos];
}

function parseClassBody(array $tokens, int $pos, ?string $namespace, array $uses, bool $collectBodies = false): array {
    $n = count($tokens);
    $pos++; // skip '{'

    $methods = [];
    $properties = [];
    $constants = [];
    $traits = [];

    $pendingAttrs = [];
    $pendingMods = [];

    while ($pos < $n) {
        $pos = skipTrivia($tokens, $pos);
        if ($pos >= $n) break;
        $t = $tokens[$pos];
        if ($t['id'] === 0 && $t['text'] === '}') { $pos++; break; }

        if ($t['id'] === T_ATTRIBUTE) {
            [$attrs, $pos] = parseAttributeGroup($tokens, $pos);
            $pendingAttrs = array_merge($pendingAttrs, $attrs);
            continue;
        }
        if ($t['id'] === T_PUBLIC || $t['id'] === T_PROTECTED || $t['id'] === T_PRIVATE
            || $t['id'] === T_STATIC || $t['id'] === T_FINAL || $t['id'] === T_ABSTRACT
            || $t['id'] === T_READONLY || $t['id'] === T_VAR) {
            $pendingMods[] = strtolower($t['text']);
            $pos++;
            continue;
        }
        if ($t['id'] === T_USE) {
            $pos++;
            while ($pos < $n) {
                $pos = skipTrivia($tokens, $pos);
                $tname = consumeName($tokens, $pos);
                if ($tname !== '') $traits[] = resolveName($tname, $namespace, $uses);
                $pos = skipTrivia($tokens, $pos);
                if ($pos < $n && $tokens[$pos]['id'] === 0 && $tokens[$pos]['text'] === ',') { $pos++; continue; }
                break;
            }
            while ($pos < $n) {
                $tt = $tokens[$pos];
                if ($tt['id'] === 0 && $tt['text'] === ';') { $pos++; break; }
                if ($tt['id'] === 0 && $tt['text'] === '{') { $pos = skipBalanced($tokens, $pos, '{', '}'); break; }
                $pos++;
            }
            $pendingAttrs = []; $pendingMods = [];
            continue;
        }
        if ($t['id'] === T_FUNCTION) {
            [$method, $pos] = parseMethod($tokens, $pos, $namespace, $uses, $pendingAttrs, $pendingMods, $collectBodies);
            $methods[] = $method;
            $pendingAttrs = []; $pendingMods = [];
            continue;
        }
        if ($t['id'] === T_CONST) {
            [$consts, $pos] = parseConst($tokens, $pos, $pendingAttrs, $pendingMods);
            foreach ($consts as $c) $constants[] = $c;
            $pendingAttrs = []; $pendingMods = [];
            continue;
        }
        if ($t['id'] === T_VARIABLE) {
            [$prop, $pos] = parseProperty($tokens, $pos, $pendingAttrs, $pendingMods, null);
            $properties[] = $prop;
            $pendingAttrs = []; $pendingMods = [];
            continue;
        }
        // Type expression preceding T_VARIABLE (typed property).
        if (isNamePart($t)
            || $t['id'] === T_ARRAY
            || $t['id'] === T_CALLABLE
            || $t['id'] === T_STATIC
            || ($t['id'] === 0 && ($t['text'] === '?' || $t['text'] === '|' || $t['text'] === '&'))
        ) {
            $typeStart = $pos;
            while ($pos < $n) {
                $tt = $tokens[$pos];
                if ($tt['id'] === T_VARIABLE) break;
                if ($tt['id'] === 0 && ($tt['text'] === ';' || $tt['text'] === '{' || $tt['text'] === '}')) break;
                $pos++;
            }
            if ($pos < $n && $tokens[$pos]['id'] === T_VARIABLE) {
                $type = trim(implode('', array_map(fn($tk) => $tk['text'], array_slice($tokens, $typeStart, $pos - $typeStart))));
                [$prop, $pos] = parseProperty($tokens, $pos, $pendingAttrs, $pendingMods, $type);
                $properties[] = $prop;
            }
            $pendingAttrs = []; $pendingMods = [];
            continue;
        }
        $pos++;
    }

    return [[
        'methods' => $methods,
        'properties' => $properties,
        'constants' => $constants,
        'traits_used' => $traits,
    ], $pos];
}

function parseMethod(array $tokens, int $pos, ?string $namespace, array $uses, array $attrs, array $mods, bool $collectBody = false): array {
    $n = count($tokens);
    $pos++; // skip T_FUNCTION
    $pos = skipTrivia($tokens, $pos);
    if ($pos < $n && $tokens[$pos]['id'] === 0 && $tokens[$pos]['text'] === '&') $pos++;
    $pos = skipTrivia($tokens, $pos);
    if ($pos >= $n || $tokens[$pos]['id'] !== T_STRING) {
        return [[
            'name' => '', 'attributes' => $attrs, 'modifiers' => $mods,
            'parameters' => [], 'body_text' => '', 'line' => 0,
        ], $pos];
    }
    $name = $tokens[$pos]['text'];
    $line = $tokens[$pos]['line'];
    $pos++;
    $pos = skipTrivia($tokens, $pos);

    $params = [];
    if ($pos < $n && $tokens[$pos]['id'] === 0 && $tokens[$pos]['text'] === '(') {
        [$params, $pos] = parseMethodParams($tokens, $pos, $namespace, $uses);
    }
    while ($pos < $n) {
        $t = $tokens[$pos];
        if ($t['id'] === 0 && ($t['text'] === '{' || $t['text'] === ';')) break;
        $pos++;
    }
    $bodyText = '';
    if ($pos < $n && $tokens[$pos]['id'] === 0 && $tokens[$pos]['text'] === '{') {
        $start = $pos;
        $pos = skipBalanced($tokens, $pos, '{', '}');
        if ($collectBody) {
            $bodyText = implode('', array_map(fn($tk) => $tk['text'], array_slice($tokens, $start, $pos - $start)));
        }
    } elseif ($pos < $n && $tokens[$pos]['id'] === 0 && $tokens[$pos]['text'] === ';') {
        $pos++;
    }

    return [[
        'name' => $name,
        'line' => $line,
        'attributes' => $attrs,
        'modifiers' => $mods,
        'parameters' => $params,
        'body_text' => $bodyText,
    ], $pos];
}

function parseMethodParams(array $tokens, int $pos, ?string $namespace, array $uses): array {
    $n = count($tokens);
    $pos++; // skip '('
    $depth = 1;
    $segments = [];
    $current = [];
    while ($pos < $n && $depth > 0) {
        $t = $tokens[$pos];
        if ($t['id'] === 0) {
            if ($t['text'] === '(' || $t['text'] === '[' || $t['text'] === '{') { $depth++; $current[] = $t; $pos++; continue; }
            if ($t['text'] === ')' || $t['text'] === ']' || $t['text'] === '}') {
                $depth--;
                if ($depth === 0) {
                    if (!empty($current)) $segments[] = $current;
                    $pos++;
                    break;
                }
                $current[] = $t; $pos++; continue;
            }
            if ($t['text'] === ',' && $depth === 1) {
                $segments[] = $current; $current = []; $pos++; continue;
            }
        }
        $current[] = $t; $pos++;
    }
    $params = [];
    foreach ($segments as $seg) {
        $params[] = parseSingleParam($seg, $namespace, $uses);
    }
    return [$params, $pos];
}

function parseSingleParam(array $seg, ?string $namespace, array $uses): array {
    $seg = array_values(array_filter($seg, fn($t) => !isTrivia($t)));
    $n = count($seg);
    $i = 0;

    // Skip attribute groups.
    while ($i < $n && $seg[$i]['id'] === T_ATTRIBUTE) {
        $depth = 1; $i++;
        while ($i < $n && $depth > 0) {
            if ($seg[$i]['id'] === 0 && $seg[$i]['text'] === '[') $depth++;
            elseif ($seg[$i]['id'] === 0 && $seg[$i]['text'] === ']') $depth--;
            $i++;
        }
    }
    $promoted = false;
    while ($i < $n && ($seg[$i]['id'] === T_PUBLIC || $seg[$i]['id'] === T_PROTECTED
        || $seg[$i]['id'] === T_PRIVATE || $seg[$i]['id'] === T_READONLY)) {
        $promoted = true;
        $i++;
    }
    $typeStart = $i;
    while ($i < $n) {
        $t = $seg[$i];
        if ($t['id'] === T_VARIABLE) break;
        if ($t['id'] === 0 && $t['text'] === '&') break;
        if ($t['id'] === T_ELLIPSIS) break;
        $i++;
    }
    $type = null;
    if ($i > $typeStart) {
        $type = trim(implode('', array_map(fn($t) => $t['text'], array_slice($seg, $typeStart, $i - $typeStart))));
        if ($type === '') $type = null;
    }
    while ($i < $n && (($seg[$i]['id'] === 0 && $seg[$i]['text'] === '&') || $seg[$i]['id'] === T_ELLIPSIS)) $i++;
    $name = null;
    if ($i < $n && $seg[$i]['id'] === T_VARIABLE) {
        $name = $seg[$i]['text'];
    }
    return ['name' => $name, 'type' => $type, 'promoted' => $promoted];
}

function parseProperty(array $tokens, int $pos, array $attrs, array $mods, ?string $type): array {
    $n = count($tokens);
    if ($pos >= $n || $tokens[$pos]['id'] !== T_VARIABLE) {
        return [['name' => null, 'attributes' => $attrs, 'modifiers' => $mods, 'type' => $type, 'line' => 0], $pos];
    }
    $name = $tokens[$pos]['text']; // includes leading $
    $line = $tokens[$pos]['line'];
    $pos++;
    while ($pos < $n) {
        $t = $tokens[$pos];
        if ($t['id'] === 0 && $t['text'] === ';') { $pos++; break; }
        $pos++;
    }
    return [[
        'name' => substr($name, 1),
        'line' => $line,
        'attributes' => $attrs,
        'modifiers' => $mods,
        'type' => $type,
    ], $pos];
}

function parseConst(array $tokens, int $pos, array $attrs, array $mods): array {
    $n = count($tokens);
    $pos++; // skip T_CONST
    $consts = [];
    while ($pos < $n) {
        $pos = skipTrivia($tokens, $pos);
        if ($pos >= $n) break;
        if ($tokens[$pos]['id'] !== T_STRING) break;
        $name = $tokens[$pos]['text'];
        $line = $tokens[$pos]['line'];
        $pos++;
        $pos = skipTrivia($tokens, $pos);
        $value = null;
        if ($pos < $n && $tokens[$pos]['id'] === 0 && $tokens[$pos]['text'] === '=') {
            $pos++;
            $valueTokens = [];
            $depth = 0;
            while ($pos < $n) {
                $t = $tokens[$pos];
                if ($t['id'] === 0) {
                    if ($t['text'] === '(' || $t['text'] === '[' || $t['text'] === '{') $depth++;
                    elseif ($t['text'] === ')' || $t['text'] === ']' || $t['text'] === '}') {
                        if ($depth === 0) break;
                        $depth--;
                    }
                    if ($depth === 0 && ($t['text'] === ';' || $t['text'] === ',')) break;
                }
                $valueTokens[] = $t;
                $pos++;
            }
            $value = parseValueTokens($valueTokens);
        }
        $consts[] = [
            'name' => $name,
            'line' => $line,
            'value' => $value,
            'attributes' => $attrs,
            'modifiers' => $mods,
        ];
        $pos = skipTrivia($tokens, $pos);
        if ($pos < $n && $tokens[$pos]['id'] === 0 && $tokens[$pos]['text'] === ',') { $pos++; continue; }
        break;
    }
    while ($pos < $n && !($tokens[$pos]['id'] === 0 && $tokens[$pos]['text'] === ';')) $pos++;
    if ($pos < $n) $pos++;
    return [$consts, $pos];
}


// ===========================================================================
// Collectors per --kind.
// ===========================================================================

function collectClasses(array $parsed): array {
    $items = [];
    $parentMap = buildClassParentMap($parsed);
    foreach ($parsed as $path => $f) {
        foreach ($f['classes'] as $cls) {
            $items[] = [
                'fqn' => $cls['fqn'],
                'kind' => $cls['kind'],
                'is_abstract' => (bool)($cls['is_abstract'] ?? false),
                'file' => $path,
                'line' => $cls['line'],
                'extends' => $cls['extends'] ?? null,
                'parent_chain' => collectParentChain($cls['fqn'] ?? '', $parentMap),
                'implements' => $cls['implements'] ?? [],
                'traits_used' => $cls['traits_used'] ?? [],
                'attributes' => array_map(
                    fn($a) => ['name' => $a['name'], 'arguments' => $a['arguments']],
                    $cls['attributes']
                ),
            ];
        }
    }
    return ['kind' => 'class', 'items' => $items];
}

/**
 * Walk inheritance chain from $startFqn upward and return the list of resolved
 * parent FQNs (max depth 5). Stops on cycle or unknown parent.
 *
 * Used by `_classify_kind` to surface CLI commands defined as
 * `App\Console\BaseCommand → Symfony\Component\Console\Command\Command`.
 */
function collectParentChain(string $startFqn, array $parentMap, int $maxDepth = 5): array {
    if ($startFqn === '') return [];
    $chain = [];
    $current = $startFqn;
    $seen = [];
    for ($d = 0; $d < $maxDepth; $d++) {
        $parent = $parentMap[$current] ?? null;
        if ($parent === null || isset($seen[$parent])) break;
        $chain[] = $parent;
        $seen[$parent] = true;
        $current = $parent;
    }
    return $chain;
}

function collectSymbols(array $parsed): array {
    $items = [];
    foreach ($parsed as $path => $f) {
        foreach ($f['classes'] as $cls) {
            $items[] = [
                'fqn' => $cls['fqn'],
                'kind' => $cls['kind'],
                'file' => $path,
                'line' => $cls['line'],
                'namespace' => $f['namespace'],
            ];
        }
    }
    return ['kind' => 'symbols', 'items' => $items];
}

function collectRoutes(array $parsed): array {
    $items = [];
    foreach ($parsed as $path => $f) {
        foreach ($f['classes'] as $cls) {
            $classPathPrefix = '';
            $classRoute = findRouteAttr($cls['attributes']);
            if ($classRoute !== null) {
                $classPathPrefix = extractRoutePath($classRoute) ?? '';
            }
            foreach ($cls['methods'] as $m) {
                foreach ($m['attributes'] as $attr) {
                    if (lastNamePart($attr['name']) !== 'Route') continue;
                    $subPath = extractRoutePath($attr) ?? '';
                    $effective = $classPathPrefix . $subPath;
                    $items[] = [
                        'route_name' => extractNamedString($attr, 'name'),
                        'path' => $effective,
                        'class_path_prefix' => $classPathPrefix,
                        'method_path' => $subPath,
                        'methods' => extractStringList($attr, 'methods'),
                        'controller' => $cls['fqn'] . '::' . $m['name'],
                        'file' => $path,
                        'line' => $m['line'],
                    ];
                }
            }
        }
    }
    return ['kind' => 'routes', 'items' => $items];
}

function findRouteAttr(array $attrs): ?array {
    foreach ($attrs as $a) {
        if (lastNamePart($a['name']) === 'Route') return $a;
    }
    return null;
}

function extractRoutePath(array $attr): ?string {
    if (isset($attr['arguments']['named']['path'])) {
        $v = $attr['arguments']['named']['path'];
        if ($v['type'] === 'string') return $v['value'];
    }
    if (!empty($attr['arguments']['positional'])) {
        $v = $attr['arguments']['positional'][0];
        if ($v['type'] === 'string') return $v['value'];
    }
    return null;
}

function extractNamedString(array $attr, string $key): ?string {
    if (!isset($attr['arguments']['named'][$key])) return null;
    $v = $attr['arguments']['named'][$key];
    return $v['type'] === 'string' ? $v['value'] : null;
}

function extractStringList(array $attr, string $key): array {
    if (!isset($attr['arguments']['named'][$key])) return [];
    $v = $attr['arguments']['named'][$key];
    if ($v['type'] === 'string') return [$v['value']];
    if ($v['type'] !== 'array') return [];
    $out = [];
    foreach ($v['value'] as $item) {
        if (isset($item['value']) && $item['value']['type'] === 'string') {
            $out[] = $item['value']['value'];
        }
    }
    return $out;
}

function collectForms(array $parsed): array {
    $items = [];
    $parentMap = buildClassParentMap($parsed);
    $abstractTypeFqns = ['Symfony\\Component\\Form\\AbstractType'];
    foreach ($parsed as $path => $f) {
        foreach ($f['classes'] as $cls) {
            if (!empty($cls['is_abstract'])) continue;
            // M6: strictly require `extends Symfony\Component\Form\AbstractType` —
            // directly or via a project-local base type. FQN-first prevents
            // false positives from any other class named `AbstractType`.
            if (!in_array($cls['extends'], $abstractTypeFqns, true)
                && !inheritsFromFqns($cls['fqn'], $abstractTypeFqns, $parentMap)) {
                continue;
            }

            $configureBody = '';
            foreach ($cls['methods'] as $m) {
                if ($m['name'] === 'configureOptions') { $configureBody = $m['body_text']; break; }
            }

            $dataClass = null;
            $csrf = null;
            $allowExtra = null;
            if ($configureBody !== '') {
                if (preg_match("/['\"]data_class['\"]\\s*=>\\s*([A-Za-z_\\\\][A-Za-z0-9_\\\\]*)\\s*::\\s*class/s", $configureBody, $m1)) {
                    $dataClass = resolveName($m1[1], $f['namespace'], $f['uses']);
                } elseif (preg_match("/['\"]data_class['\"]\\s*=>\\s*'([^']+)'/", $configureBody, $m1)) {
                    $dataClass = $m1[1];
                } elseif (preg_match("/['\"]data_class['\"]\\s*=>\\s*\"([^\"]+)\"/", $configureBody, $m1)) {
                    $dataClass = $m1[1];
                }
                if (preg_match("/['\"]csrf_protection['\"]\\s*=>\\s*(true|false)/i", $configureBody, $m2)) {
                    $csrf = strtolower($m2[1]) === 'true';
                }
                if (preg_match("/['\"]allow_extra_fields['\"]\\s*=>\\s*(true|false)/i", $configureBody, $m3)) {
                    $allowExtra = strtolower($m3[1]) === 'true';
                }
            }

            $items[] = [
                'class' => $cls['fqn'],
                'file' => $path,
                'line' => $cls['line'],
                'data_class' => $dataClass,
                'csrf_protection' => $csrf,
                'allow_extra_fields' => $allowExtra,
            ];
        }
    }
    return ['kind' => 'forms', 'items' => $items];
}

function collectVoters(array $parsed): array {
    $items = [];
    $parentMap = buildClassParentMap($parsed);
    $voterFqns = ['Symfony\\Component\\Security\\Core\\Authorization\\Voter\\Voter'];
    foreach ($parsed as $path => $f) {
        foreach ($f['classes'] as $cls) {
            if (!empty($cls['is_abstract'])) continue;
            // FQN-first: only Symfony's Voter base counts. The legacy
            // suffix fallback (`/Voter$/`) is kept to surface naming-only
            // matches (older projects implementing VoterInterface manually
            // without extending the base class) but covers a narrow edge.
            $isVoter = in_array($cls['extends'], $voterFqns, true)
                || inheritsFromFqns($cls['fqn'], $voterFqns, $parentMap)
                || preg_match('/Voter$/', $cls['name']);
            if (!$isVoter) continue;

            // Constants: name → string value (if string literal).
            $constMap = [];
            foreach ($cls['constants'] as $c) {
                if (isset($c['value']) && $c['value']['type'] === 'string') {
                    $constMap[$c['name']] = $c['value']['value'];
                }
            }

            // Bodies of supports() / voteOnAttribute().
            $supportsBody = '';
            $voteBody = '';
            $supportsSubjectType = null;
            $voteSubjectType = null;
            foreach ($cls['methods'] as $m) {
                if ($m['name'] === 'supports') {
                    $supportsBody = $m['body_text'];
                    foreach ($m['parameters'] as $p) {
                        if ($p['name'] === '$subject') $supportsSubjectType = $p['type'];
                    }
                }
                if ($m['name'] === 'voteOnAttribute') {
                    $voteBody = $m['body_text'];
                    foreach ($m['parameters'] as $p) {
                        if ($p['name'] === '$subject') $voteSubjectType = $p['type'];
                    }
                }
            }
            $combined = $supportsBody . "\n" . $voteBody;

            // M3: only resolve attributes referenced via self::/static::CONST.
            // Plain SCREAMING_SNAKE_CASE string match (`'EUR'`, `'AES_GCM'`) was
            // dropped — too many false positives from log tags / currency codes.
            $attrSet = [];
            if (preg_match_all('/(?:self|static)::([A-Z_][A-Z_0-9]*)/', $combined, $mm)) {
                foreach ($mm[1] as $cname) {
                    $attrSet[$constMap[$cname] ?? $cname] = true;
                }
            }

            $subjectSet = [];
            if (preg_match_all('/\\$subject\\s+instanceof\\s+([A-Za-z_\\\\][A-Za-z0-9_\\\\]*)/', $combined, $mm3)) {
                foreach ($mm3[1] as $sn) {
                    $subjectSet[resolveName($sn, $f['namespace'], $f['uses'])] = true;
                }
            }
            foreach ([$supportsSubjectType, $voteSubjectType] as $tp) {
                if ($tp === null) continue;
                $tp = ltrim($tp, '?');
                if ($tp === '' || preg_match('/^(string|int|float|bool|array|object|mixed|iterable|callable|void|never|self|static|parent)$/i', $tp)) continue;
                $subjectSet[resolveName($tp, $f['namespace'], $f['uses'])] = true;
            }

            $items[] = [
                'class' => $cls['fqn'],
                'file' => $path,
                'line' => $cls['line'],
                'attributes' => array_keys($attrSet),
                'subjects' => array_keys($subjectSet),
            ];
        }
    }
    return ['kind' => 'voters', 'items' => $items];
}

function collectGroups(array $parsed): array {
    $items = [];
    foreach ($parsed as $path => $f) {
        foreach ($f['classes'] as $cls) {
            foreach ($cls['properties'] as $p) {
                $g = collectGroupsFromAttrs($p['attributes']);
                if (!empty($g)) {
                    $items[] = [
                        'class' => $cls['fqn'], 'member' => $p['name'], 'kind' => 'property',
                        'groups' => $g, 'file' => $path, 'line' => $p['line'] ?? null,
                    ];
                }
            }
            foreach ($cls['methods'] as $m) {
                $g = collectGroupsFromAttrs($m['attributes']);
                if (!empty($g)) {
                    $items[] = [
                        'class' => $cls['fqn'], 'member' => $m['name'], 'kind' => 'method',
                        'groups' => $g, 'file' => $path, 'line' => $m['line'] ?? null,
                    ];
                }
            }
        }
    }
    return ['kind' => 'serializer-groups', 'items' => $items];
}

function collectGroupsFromAttrs(array $attrs): array {
    $out = [];
    foreach ($attrs as $a) {
        if (lastNamePart($a['name']) !== 'Groups') continue;
        if (empty($a['arguments']['positional'])) continue;
        $v = $a['arguments']['positional'][0];
        if ($v['type'] === 'array') {
            foreach ($v['value'] as $item) {
                if (isset($item['value']) && $item['value']['type'] === 'string') $out[] = $item['value']['value'];
            }
        } elseif ($v['type'] === 'string') {
            $out[] = $v['value'];
        }
    }
    return $out;
}

function collectEasyadminCrud(array $parsed): array {
    $items = [];
    $parentMap = buildClassParentMap($parsed);
    $easyadminFqns = ['EasyCorp\\Bundle\\EasyAdminBundle\\Controller\\AbstractCrudController'];
    foreach ($parsed as $path => $f) {
        foreach ($f['classes'] as $cls) {
            if (!empty($cls['is_abstract'])) continue;
            if (!in_array($cls['extends'], $easyadminFqns, true)
                && !inheritsFromFqns($cls['fqn'], $easyadminFqns, $parentMap)) {
                continue;
            }

            $entityFqcn = null;
            $configureFields = [];
            $actionsDisabled = [];
            $pageTitles = [];
            $unresolvedFields = false;

            foreach ($cls['methods'] as $m) {
                $body = $m['body_text'] ?? '';
                if ($body === '') continue;

                if ($m['name'] === 'getEntityFqcn') {
                    if (preg_match('/return\s+([A-Za-z_\\\\][A-Za-z0-9_\\\\]*)\s*::\s*class\s*;/s', $body, $mm)) {
                        $entityFqcn = resolveName($mm[1], $f['namespace'], $f['uses']);
                    }
                } elseif ($m['name'] === 'configureFields') {
                    $parsedFields = parseEasyadminFields($body);
                    $configureFields = $parsedFields['fields'];
                    $unresolvedFields = $parsedFields['unresolved'];
                } elseif ($m['name'] === 'configureActions') {
                    if (preg_match_all('/->disable\s*\(([^)]*)\)/s', $body, $mm)) {
                        foreach ($mm[1] as $argList) {
                            if (preg_match_all('/Action::([A-Z_]+)/', $argList, $am)) {
                                foreach ($am[1] as $aName) {
                                    $actionsDisabled[strtolower($aName)] = true;
                                }
                            }
                        }
                    }
                } elseif ($m['name'] === 'configureCrud') {
                    if (preg_match_all(
                        '/->setPageTitle\s*\(\s*[\'"]([a-z]+)[\'"]\s*,\s*[\'"]([^\'"]*)[\'"]\s*\)/s',
                        $body, $mm, PREG_SET_ORDER
                    )) {
                        foreach ($mm as $row) {
                            $pageTitles[$row[1]] = $row[2];
                        }
                    }
                }
            }

            // Force JSON object shape for empty associative maps (PHP empty array → []).
            $pageTitlesOut = empty($pageTitles) ? (object) [] : $pageTitles;

            $items[] = [
                'class' => $cls['fqn'],
                'file' => $path,
                'line' => $cls['line'],
                'entity_fqcn' => $entityFqcn,
                'configure_fields' => $configureFields,
                'configure_actions' => ['disabled' => array_keys($actionsDisabled)],
                'page_titles' => $pageTitlesOut,
                'unresolved_fields' => $unresolvedFields,
            ];
        }
    }
    return ['kind' => 'easyadmin-crud', 'items' => $items];
}

/**
 * Parse a configureFields() body — collect *Field::new('name', ...) calls and chained ->modifier(...) names.
 *
 * Returns ['fields' => [...], 'unresolved' => bool]. `unresolved=true` signals that
 * configureFields delegates to parent or another method (yield from, parent::configureFields,
 * yield from $this->...) — recipe should mark such CRUD as partial.
 *
 * Modifier extraction uses a paren-depth-aware scanner: `->name(` is recorded only
 * when encountered at the top of the chain (depth 0). Calls inside lambdas
 * (`formatValue(fn($v) => $v->getInner())`) and string literals do not pollute
 * the modifier list.
 */
function parseEasyadminFields(string $body): array {
    $unresolved = false;
    if (preg_match('/yield\s+from\s+(?:parent::|self::|\$this->)/', $body)
        || preg_match('/parent::configureFields\s*\(/', $body)) {
        $unresolved = true;
    }

    $fields = [];
    if (!preg_match_all(
        '/([A-Za-z_][A-Za-z0-9_]*)Field::new\s*\(\s*[\'"]([^\'"]+)[\'"]/',
        $body, $matches, PREG_OFFSET_CAPTURE
    )) {
        return ['fields' => $fields, 'unresolved' => $unresolved];
    }

    $occurrences = $matches[0];
    $count = count($occurrences);
    for ($i = 0; $i < $count; $i++) {
        $startPos = $occurrences[$i][1];
        $fieldType = $matches[1][$i][0] . 'Field';
        $name = $matches[2][$i][0];
        $endPos = ($i + 1 < $count) ? $occurrences[$i + 1][1] : strlen($body);
        $segment = substr($body, $startPos, $endPos - $startPos);

        $modifiers = scanTopLevelMethodCalls($segment);
        unset($modifiers['new']);

        $fields[] = [
            'name' => $name,
            'field_type' => $fieldType,
            'modifiers' => array_keys($modifiers),
        ];
    }
    return ['fields' => $fields, 'unresolved' => $unresolved];
}

/**
 * Scan a chained-call segment and return top-level `->method(` names as keys.
 *
 * `Field::new('foo')->setLabel('X')->formatValue(fn($v) => $v->getInner())`
 *   ⇒ ['setLabel' => true, 'formatValue' => true]   (NOT 'getInner')
 *
 * Tracks paren depth, skips contents of single/double-quoted strings and PHP
 * comments (`//`, `#`, `/* ... *​/`). Body text fed to this scanner is the
 * raw method body (token concatenation, comments included), so comment-aware
 * parsing matters in practice — `// ->oldModifier()` or `/* deprecated:
 * ->setX() *​/` inside `configureFields()` would otherwise leak into modifiers.
 * HEREDOC / NOWDOC are still uncommon enough to be left out — recipe stays
 * best-effort, biased toward false-negatives over noise.
 */
function scanTopLevelMethodCalls(string $segment): array {
    $modifiers = [];
    $len = strlen($segment);
    $depth = 0;
    $state = 'normal'; // normal | sq | dq | line_comment | block_comment
    $i = 0;
    while ($i < $len) {
        $c = $segment[$i];
        if ($state === 'sq') {
            if ($c === '\\' && $i + 1 < $len) { $i += 2; continue; }
            if ($c === '\'') { $state = 'normal'; }
            $i++;
            continue;
        }
        if ($state === 'dq') {
            if ($c === '\\' && $i + 1 < $len) { $i += 2; continue; }
            if ($c === '"') { $state = 'normal'; }
            $i++;
            continue;
        }
        if ($state === 'line_comment') {
            if ($c === "\n") { $state = 'normal'; }
            $i++;
            continue;
        }
        if ($state === 'block_comment') {
            if ($c === '*' && $i + 1 < $len && $segment[$i + 1] === '/') {
                $state = 'normal';
                $i += 2;
                continue;
            }
            $i++;
            continue;
        }
        if ($c === '/' && $i + 1 < $len && $segment[$i + 1] === '/') {
            $state = 'line_comment'; $i += 2; continue;
        }
        if ($c === '#' && !($i + 1 < $len && $segment[$i + 1] === '[')) {
            // PHP `#`-style comment. Skip; `#[` is an attribute, leave alone.
            $state = 'line_comment'; $i++; continue;
        }
        if ($c === '/' && $i + 1 < $len && $segment[$i + 1] === '*') {
            $state = 'block_comment'; $i += 2; continue;
        }
        if ($c === '\'') { $state = 'sq'; $i++; continue; }
        if ($c === '"')  { $state = 'dq'; $i++; continue; }
        if ($c === '(')  { $depth++; $i++; continue; }
        if ($c === ')')  { $depth--; $i++; continue; }
        if ($c === '-' && $i + 1 < $len && $segment[$i + 1] === '>' && $depth === 0) {
            // Try to match `->methodName(`. Whitespace tolerated between name and `(`.
            $j = $i + 2;
            while ($j < $len && ctype_space($segment[$j])) { $j++; }
            if ($j < $len && (ctype_alpha($segment[$j]) || $segment[$j] === '_')) {
                $start = $j;
                while ($j < $len && (ctype_alnum($segment[$j]) || $segment[$j] === '_')) { $j++; }
                $name = substr($segment, $start, $j - $start);
                $k = $j;
                while ($k < $len && ctype_space($segment[$k])) { $k++; }
                if ($k < $len && $segment[$k] === '(') {
                    $modifiers[$name] = true;
                    $i = $k; // re-enter loop at `(` so depth bookkeeping is consistent
                    continue;
                }
            }
        }
        $i++;
    }
    return $modifiers;
}

/**
 * Collect classes extending Sonata\AdminBundle\Admin\AbstractAdmin.
 *
 * Sonata admin classes carry recipe-relevant metadata in two places:
 *   1. `getClass(): string` — returns the entity FQN under management.
 *   2. `configureFormFields(FormMapper $form)` — `$form->add('name', ...)`.
 *
 * Like the EasyAdmin collector this is a strict-extends match (only direct
 * inheritance from AbstractAdmin / AbstractAdmin alias). Indirect chains
 * (project-local Base*Admin) are picked up later by the inheritance-graph pass.
 */
function collectSonataAdmin(array $parsed): array {
    $items = [];
    $parentMap = buildClassParentMap($parsed);
    foreach ($parsed as $path => $f) {
        foreach ($f['classes'] as $cls) {
            if (!empty($cls['is_abstract'])) continue;
            $sonataFqns = ['Sonata\\AdminBundle\\Admin\\AbstractAdmin'];
            if (!in_array($cls['extends'], $sonataFqns, true)
                && !inheritsFromFqns($cls['fqn'], $sonataFqns, $parentMap)) {
                continue;
            }

            $entityFqcn = null;
            $formFields = [];
            $unresolved = false;

            foreach ($cls['methods'] as $m) {
                $body = $m['body_text'] ?? '';
                if ($body === '') continue;

                if ($m['name'] === 'getClass') {
                    if (preg_match(
                        '/return\s+([A-Za-z_\\\\][A-Za-z0-9_\\\\]*)\s*::\s*class\s*;/s',
                        $body, $mm
                    )) {
                        $entityFqcn = resolveName($mm[1], $f['namespace'], $f['uses']);
                    } elseif (preg_match(
                        '/return\s+[\'"]([A-Za-z_\\\\][A-Za-z0-9_\\\\]*)[\'"]\s*;/s',
                        $body, $mm
                    )) {
                        // PHP source `return 'App\\Entity\\User';` keeps the
                        // double-backslash in the captured token text. Normalise
                        // to the resolved FQN form (single backslash) used by
                        // voter subjects so admin_authz_coverage cross-check
                        // matches.
                        $entityFqcn = ltrim(str_replace('\\\\', '\\', $mm[1]), '\\');
                    }
                } elseif ($m['name'] === 'configureFormFields') {
                    if (preg_match('/parent::configureFormFields\s*\(/', $body)) {
                        $unresolved = true;
                    }
                    if (preg_match_all(
                        '/->add\s*\(\s*[\'"]([A-Za-z_][A-Za-z0-9_]*)[\'"]/s',
                        $body, $mm
                    )) {
                        foreach ($mm[1] as $fname) {
                            if (!in_array($fname, $formFields, true)) {
                                $formFields[] = $fname;
                            }
                        }
                    }
                }
            }

            $items[] = [
                'class' => $cls['fqn'],
                'file' => $path,
                'line' => $cls['line'],
                'entity_fqcn' => $entityFqcn,
                'form_fields' => $formFields,
                'unresolved_fields' => $unresolved,
            ];
        }
    }
    return ['kind' => 'sonata-admin', 'items' => $items];
}
