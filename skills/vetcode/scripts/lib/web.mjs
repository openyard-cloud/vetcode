// Vulnerability candidates in application code (JavaScript/TypeScript, Python, PHP, Go, Ruby):
// injection, XSS, path traversal, SSRF, open redirects, unsafe deserialization, weak crypto,
// broken TLS, CORS, debug mode, mass assignment and client-exposed secrets.
// These are candidates: each one needs a look at where the input comes from.

const JS = /\.(c|m)?(j|t)sx?$|\.(vue|svelte|astro)$/i;
const PY = /\.pyw?$/i;
const PHP = /\.(php|phtml)$/i;
const GO = /\.go$/i;
const RB = /\.(rb|erb)$/i;
const SERVER = /\.(c|m)?(j|t)sx?$|\.(py|php|go|rb)$/i;
const ANY = /\.(c|m)?(j|t)sx?$|\.(vue|svelte|astro|py|php|phtml|go|rb|erb|html?|jinja2?|j2|njk|hbs|handlebars|ejs|twig|liquid|mustache)$/i;
const TEMPLATE = /\.(html?|jinja2?|j2|njk|hbs|handlebars|ejs|twig|erb|liquid|mustache)$|\.blade\.php$/i;

const USER_JS = String.raw`(?:req|request|ctx\.request|event|c\.req)\.(?:query|body|params|headers|cookies|url|path|search)`;
const USER_PY = String.raw`request\.(?:args|form|values|json|get_json\(\)|files|data|GET|POST|body|query_params|path_params|headers|cookies)`;
const USER_PHP = String.raw`\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)`;

const rule = r => ({ category: "web", confidence: "medium", ...r });
const SQL = "Build queries with parameters (`?`, `$1`, `:name`) or the ORM's query builder, never by gluing strings.";

// A template literal whose every ${…} is a table or column name, a list of placeholders or a
// joined list of clauses.
const SQL_PARTS_ONLY = /^(?:(?!\$\{).)*(?:\$\{\s*\w*(?:[Tt]able|[Cc]olumn|[Pp]laceholders?|[Cc]lauses?|[Ww]here|[Ff]ields|[Cc]ols|[Ss]ets|[Oo]rder)\w*(?:\.join\([^)]*\))?\s*\}(?:(?!\$\{).)*)+$/;
// Names that hold a piece of a query rather than a value.
const SQL_FRAGMENT = /(?:\+|\.)\s*\$?(?:strings\.Join\(|\w*[Pp]laceholders?\w*\(|\w*(?:[Cc]lause|[Ww]here\w*|[Cc]ond\w*|[Ff]ields|[Cc]olumns|[Cc]ols|[Ss]ets|[Tt]able\w*|[Oo]rderBy\w*|[Ss]ql\w*)\b|\w*\.?[Qq]uote\w*\()/;

export const WEB_RULES = [
  // Injection
  rule({ id: "sql-template-literal", severity: "high", title: "SQL built with a template literal", files: JS,
    re: /\.(?:query|execute|exec|raw|prepare|run|all|get|unsafe)\s*\(\s*`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE|MERGE|REPLACE|WITH)\b[^`]*\$\{/i,
    unless: SQL_PARTS_ONLY,
    why: "Values pasted into SQL text let an attacker change the query (SQL injection).", fix: SQL }),
  rule({ id: "sql-fragments", severity: "low", title: "SQL assembled from fragments", files: JS,
    re: /\.(?:query|execute|exec|raw|prepare|run|all|get|unsafe)\s*\(\s*`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE|MERGE|REPLACE|WITH)\b[^`]*\$\{/i, requires: /\$\{/, unlessNot: SQL_PARTS_ONLY,
    why: "Table and column names, placeholder lists and joined clauses are put into the query text. That is safe when each is made of names and placeholders, and injectable if one carries a value.",
    fix: "Check how each fragment is built; values belong in the query arguments." }),
  rule({ id: "sql-unsafe-raw", severity: "high", title: "Raw SQL method that does not escape", files: JS,
    re: /\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(|\bsequelize\.literal\s*\([^)]*\$\{|\bknex\.raw\s*\(\s*`[^`]*\$\{|\.whereRaw\s*\(\s*`[^`]*\$\{/,
    // Placeholders in the text and a list of bindings after it: the values are bound, the rest is the dialect.
    unless: /`[^`]*\?[^`]*`\s*,\s*\[|\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(\s*[\w.]+\s*,/,
    why: "These APIs pass the string to the database as-is.", fix: SQL }),
  rule({ id: "sql-concat", severity: "high", title: "SQL built by string concatenation", files: SERVER,
    re: /["'`]\s*(?:SELECT\b[^"'`]*\bFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b[^"'`]*["'`]\s*(?:\+|\.)\s*\$?[A-Za-z_]/i,
    // Joining a list of conditions, a placeholder helper or a clause built elsewhere is how query
    // builders work; that is the rule below.
    unless: SQL_FRAGMENT,
    why: "Concatenated SQL is injectable whenever a piece comes from a user.", fix: SQL }),
  rule({ id: "sql-fragments", severity: "low", title: "SQL assembled from fragments", files: SERVER,
    re: new RegExp(String.raw`["'\x60]\s*(?:SELECT\b[^"'\x60]*\bFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b[^"'\x60]*["'\x60]\s*` + SQL_FRAGMENT.source, "i"),
    why: "The query text is put together from pieces (conditions, placeholders, a clause). That is safe when every piece is made of column names and placeholders, and injectable if one of them carries a value.",
    fix: "Check how each fragment is built; values belong in the query arguments." }),
  rule({ id: "sql-python-format", severity: "high", title: "SQL built with f-string, % or .format()", files: PY,
    unless: /^(?:(?!\{).)*(?:\{[\w.]*(?:__tablename__|[Tt]able\w*|\w*[Cc]lause\w*|assignments|columns|cols|fields|placeholders|schema)\}(?:(?!\{).)*)+$/,
    re: /\.(?:execute|executemany|executescript|raw|extra)\s*\(\s*(?:f["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b|["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*(?:%|\.format\())|\btext\s*\(\s*f["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b/i,
    why: "Formatting values into SQL text allows SQL injection.", fix: "Use `cursor.execute(sql, params)` / SQLAlchemy bound parameters." }),
  rule({ id: "sql-php-input", severity: "critical", confidence: "high", title: "Request data inside a SQL call", files: PHP,
    re: new RegExp(String.raw`\b(?:mysql_query|mysqli_query|pg_query|->query|->exec|->prepare)\s*\([^;]*${USER_PHP}`),
    why: "Request parameters go straight into SQL.", fix: "Use PDO/mysqli prepared statements with bound parameters." }),
  rule({ id: "sql-go-sprintf", severity: "high", title: "SQL built with fmt.Sprintf", files: GO,
    // The formatted string has to be the query itself, not one of its bound arguments.
    re: /\.(?:Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext|Raw|Where)\s*\(\s*(?:ctx\s*,\s*)?fmt\.Sprintf\(/,
    // Names of tables and columns cannot be bound: a statement that only formats quoted identifiers
    // and numbers, or that changes the schema, has no value to pass as an argument.
    unless: /fmt\.Sprintf\(\s*"(?:`%s`|\[%s\]|%[dt]|%%|[^"%\n])*"|fmt\.Sprintf\(\s*["`]\s*(?:ALTER|DROP|CREATE|TRUNCATE|RENAME|SET\s+IDENTITY_INSERT|VACUUM|ANALYZE|REINDEX)\b/i,
    why: "Formatted SQL is injectable.", fix: "Pass values as query arguments (`db.Query(sql, a, b)`)." }),
  rule({ id: "nosql-injection", severity: "high", title: "Request object used directly as a database filter", files: JS,
    // A method called deleteMany on a service class is not a MongoDB filter.
    requires: /mongoose|mongodb|MongoClient|\bObjectId\b|\.collection\s*\(|new\s+Schema\s*\(/,
    re: new RegExp(String.raw`\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|countDocuments|aggregate)\s*\(\s*${USER_JS}\s*[,)]`),
    why: "An attacker can send operators like `{\"$ne\": null}` to match any record (NoSQL injection).", fix: "Pick the fields you expect and validate their types before querying." }),
  rule({ id: "cmd-injection-js", severity: "high", title: "Shell command built from strings", files: JS,
    re: /(?:^|[^.\w]|\b(?:child_process|childProcess|cp|proc)\.)(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*\+)|\bspawn(?:Sync)?\s*\([^)]*shell\s*:\s*true|\$`[^`]*\$\{/,
    requires: /child_process|\bexeca\b|\bshelljs\b|from\s+["']zx["']|require\(["']zx["']\)/,
    why: "A shell parses the whole string, so input containing `;`, `|` or `$()` runs extra commands.", fix: "Use `execFile`/`spawn` with an argument array and no shell; validate input against an allow-list." }),
  rule({ id: "cmd-injection-py", severity: "high", title: "Shell command built from strings", files: PY,
    re: /\bsubprocess\.\w+\([^)]*shell\s*=\s*True|\bos\.(?:system|popen)\s*\(\s*(?:f["']|["'][^"']*["']\s*(?:\+|%)|[\w.]+\s*\+|[^)]*\.format\()/,
    why: "The shell runs anything injected into the string.", fix: "Use `subprocess.run([...], shell=False)` with a list of arguments." }),
  rule({ id: "cmd-injection-php", severity: "critical", confidence: "high", title: "Request data in a shell command", files: PHP,
    re: new RegExp(String.raw`\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\([^;]*${USER_PHP}|\x60[^\x60]*${USER_PHP}`),
    why: "Remote command execution.", fix: "Avoid the shell; if unavoidable, use escapeshellarg on every argument and an allow-list." }),
  rule({ id: "code-eval-input", severity: "critical", confidence: "high", title: "User input evaluated as code", files: SERVER,
    // `exec` is code execution in Python but a shell call in Node (covered by cmd-injection-js).
    re: new RegExp(String.raw`\b(?:eval|Function|assert|create_function)\s*\([^;\n]*(?:${USER_JS}|${USER_PY}|${USER_PHP}|\binput\s*\()|\bexec\s*\([^;\n]*(?:${USER_PY}|\binput\s*\()`),
    why: "Remote code execution.", fix: "Never evaluate input; parse it (JSON.parse, ast.literal_eval) instead." }),
  rule({ id: "code-eval-dynamic", severity: "medium", confidence: "low", title: "eval / new Function on a non-literal", files: JS, skip: /\.min\.\w+$/,
    re: /(?<![.\w])eval\s*\(\s*(?!["'`])[A-Za-z_$]|\bnew\s+Function\s*\(\s*(?!["'`])[A-Za-z_$]/,
    why: "If the value can come from a user, this is code execution.", fix: "Replace with a parser or a lookup table." }),
  rule({ id: "ssti", severity: "critical", title: "Template rendered from user input (SSTI)", files: PY,
    re: new RegExp(String.raw`\brender_template_string\s*\([^)]*${USER_PY}|\b(?:Template|Environment\(\)\.from_string)\s*\([^)]*${USER_PY}`),
    why: "Jinja templates can run Python: server-side template injection is remote code execution.", fix: "Render a fixed template and pass the input as a variable." }),

  // XSS
  rule({ id: "xss-inner-html", severity: "medium", perFile: true, title: "HTML set from a variable", files: JS,
    re: /\.(?:innerHTML|outerHTML)\s*\+?=\s*(?!\s*["'`][^"'`$]*["'`]\s*;?\s*$)(?!\s*["']\s*;)|\.insertAdjacentHTML\s*\([^,]+,\s*(?!["'`][^"'`$]*["'`]\s*\))|\bdocument\.write(?:ln)?\s*\(/,
    unless: /DOMPurify|sanitize|escapeHtml|escape\(|textContent|\.createHTML\(|^\s*(?:\/\/|\*)|\.(?:innerHTML|outerHTML)\s*=\s*\(?\s*(?:["'`]{2}\s*[;)]?|[\w.]*(?:[Ii]con|ICON|[Ss]vg|SVG)\w*(?:\s+as\s+\w+)?\)?\s*;?)\s*\)?\s*$/,
    why: "If any part comes from a user (or the URL), it can run script in your users' browsers (XSS).", fix: "Use `textContent`, build nodes with createElement, or sanitise with DOMPurify." }),
  rule({ id: "xss-react-dangerous", severity: "medium", perFile: true, title: "dangerouslySetInnerHTML with a variable", files: JS,
    re: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!["'`])/, unless: /DOMPurify|sanitize|__html\s*:\s*JSON\.stringify/,
    why: "React stops escaping here; user-controlled HTML becomes XSS.", fix: "Sanitise with DOMPurify, or render text instead." }),
  rule({ id: "xss-framework-raw", severity: "medium", perFile: true, title: "Raw HTML binding", files: /\.(vue|svelte|astro|html?)$/i,
    re: /\sv-html\s*=|\{@html\s|set:html\s*=/,
    // Not when what is bound is a sanitiser's output.
    unless: /(?:v-html\s*=\s*["']|\{@html\s+|set:html\s*=\s*\{?)\s*(?:await\s+)?(?:[\w$]+\.)*(?:sanitize\w*|sanitise\w*|purify\w*|clean\w*Html|xss)\s*\(/i,
    why: "These bindings skip escaping.", fix: "Bind text, or sanitise the HTML first." }),
  rule({ id: "xss-template-unescaped", severity: "medium", perFile: true, title: "Template output without escaping", files: TEMPLATE,
    // A template with no HTML element in it (a text message, an email subject) has nothing to
    // inject into; a comment used as a separator line is not markup.
    // In Blade, a raw variable or request data is the case to read; a helper call is the rule below.
    requires: /<[a-z][a-z0-9-]*(?:\s[^<>]*)?\/?>/i,
    re: /\|\s*safe\b|\{%-?\s*autoescape\s+(?:false|off)|\{!!\s*\$(?!slot\b|attributes\b)[\w>\[\]'"-]+\s*!!\}|\{!![^!]*(?:\$request\b|\brequest\(|\bold\(|\$_(?:GET|POST|REQUEST|COOKIE))[^!]*!!\}|\{\{\{[^}]+\}\}\}|(?<!["'])\.html_safe\b|\braw\s*\(/,
    why: "Unescaped output is XSS if the value can contain user text.", fix: "Use the escaped form (`{{ }}`, `<%=`), or sanitise before marking safe." }),
  // `<%-` prints raw HTML in EJS; in ERB it only trims whitespace.
  rule({ id: "xss-template-unescaped", severity: "medium", perFile: true, title: "Template output without escaping", files: /\.ejs$/i, re: /<%-(?!-)/,
    why: "Unescaped output is XSS if the value can contain user text.", fix: "Use the escaped form (`<%=`), or sanitise before printing." }),
  rule({ id: "xss-template-raw-helper", severity: "low", title: "Template prints a helper's output without escaping", files: TEMPLATE,
    re: /\{!!\s*(?![\s$])[^!]*!!\}|\{!!\s*\$[^!]*\)\s*!!\}/, unless: /\$request\b|\brequest\(|\bold\(|\$_(?:GET|POST|REQUEST|COOKIE)/,
    why: "Form builders, translations and formatters return HTML on purpose. It is XSS only if the helper passes user text through unescaped.",
    fix: "Check what the helper does with its arguments, and escape them inside it." }),
  rule({ id: "xss-php-echo", severity: "high", title: "Request data echoed into the page", files: PHP,
    re: new RegExp(String.raw`\b(?:echo|print)\b[^;]*${USER_PHP}`), unless: /htmlspecialchars|htmlentities|esc_html|esc_attr|intval|\(int\)/,
    why: "Reflected XSS.", fix: "Wrap output in htmlspecialchars($v, ENT_QUOTES, 'UTF-8')." }),
  rule({ id: "xss-jquery-html", severity: "low", confidence: "low", title: "jQuery inserts HTML from a variable", files: JS,
    re: /\$\([^)]*\)\.(?:html|append|prepend|after|before|replaceWith)\(\s*(?!["'`])[A-Za-z_$][\w$.]*\s*\)/,
    why: "These methods parse their argument as HTML.", fix: "Use `.text()` for text." }),

  // Files, URLs, redirects
  rule({ id: "path-traversal", severity: "high", title: "File path taken from the request", files: SERVER,
    re: new RegExp(String.raw`(?:\b(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|appendFile|unlink|unlinkSync|rm|rmSync|sendFile|download|open|send_file|send_from_directory|FileResponse|file_get_contents|fopen|readfile|unlink|os\.Open|ioutil\.ReadFile|os\.ReadFile|File\.read|send_file)\b|(?<![.\w])(?:include|require)(?:_once)?\b(?![?!]))\s*\(?[^;\n]*(?:${USER_JS}|${USER_PY}|${USER_PHP}|c\.(?:Query|Param|PostForm)\(|params\[)`),
    why: "`../` in the value reads or writes files outside the intended folder; with include/require it runs them.", fix: "Map the input to an allow-list, or resolve the path and check it stays inside the base folder." }),
  rule({ id: "path-upload-name", severity: "medium", title: "Uploaded file saved under the client's file name", files: SERVER,
    re: /\.originalname\b[^\n]*(?:join|resolve|writeFile|mv\(|rename)|(?:join|resolve|writeFile|rename)[^\n]*\.originalname\b|\.filename\)[^\n]*\.save\(|move_uploaded_file\s*\([^,]+,\s*[^)]*\$_FILES\[[^\]]+\]\[["']name["']\]/,
    why: "The client controls the name: `../` traversal, overwriting files, or uploading `.php`/`.html` that then runs.", fix: "Generate the stored name yourself (random id + checked extension) and keep uploads outside the web root." }),
  rule({ id: "ssrf", severity: "high", title: "Server fetches a URL from the request (SSRF)", files: SERVER,
    re: new RegExp(String.raw`(?<![.\w])(?:fetch|axios(?:\.\w+)?|got(?:\.\w+)?|needle|superagent\.\w+|https?\.(?:get|request)|requests\.(?:get|post|put|head|request)|httpx\.\w+|urlopen|urllib\.request\.urlopen|curl_setopt|file_get_contents|http\.Get|http\.NewRequest)\s*\([^;\n]*(?:${USER_JS}|${USER_PY}|${USER_PHP}|c\.Query\()`),
    why: "An attacker can make your server call internal addresses (cloud metadata at 169.254.169.254, localhost admin panels, the private network).", fix: "Allow-list hosts, resolve the address and block private/link-local ranges, and do not follow redirects blindly." }),
  rule({ id: "open-redirect", severity: "low", title: "Redirect to a URL from the request", files: SERVER,
    re: new RegExp(String.raw`\b(?:res\.redirect|redirect|ctx\.redirect|Response\.redirect|HttpResponseRedirect|RedirectResponse|http\.Redirect)\s*\([^;\n]*(?:${USER_JS}|${USER_PY}|c\.Query\()|header\s*\(\s*["']Location:\s*["']?\s*\.\s*${USER_PHP}`),
    unless: /new\s+URL\(\s*["'`]\/[^"'`]*["'`]\s*,\s*(?:req|request)(?:\.nextUrl)?\.url\s*\)/,
    why: "Phishing links on your domain (`?next=https://evil`) and stolen OAuth codes.", fix: "Only redirect to relative paths or an allow-list of hosts." }),

  // Deserialization
  rule({ id: "deserialize-python", severity: "high", title: "Unsafe deserialisation", files: PY,
    re: /\b(?:pickle|cPickle|_pickle|dill|shelve|jsonpickle)\.(?:loads?|Unpickler|open|decode)\s*\(|\bmarshal\.loads\s*\(|\byaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?C?SafeLoader)|\byaml\.(?:unsafe_load|full_load)\s*\(|torch\.load\s*\((?![^)]*weights_only\s*=\s*True)/,
    why: "Loading untrusted pickle/YAML runs arbitrary code.", fix: "Use JSON or `yaml.safe_load`; `torch.load(..., weights_only=True)`; never unpickle data from users or the network." }),
  rule({ id: "deserialize-php", severity: "high", title: "unserialize() on request data", files: PHP,
    re: new RegExp(String.raw`\bunserialize\s*\([^)]*(?:${USER_PHP}|base64_decode)`),
    why: "PHP object injection leads to code execution through gadget chains.", fix: "Use json_decode." }),
  rule({ id: "deserialize-node", severity: "high", title: "Unsafe deserialisation library", files: JS,
    re: /require\(["'](?:node-serialize|serialize-to-js|funcster)["']\)|from\s+["'](?:node-serialize|serialize-to-js|funcster)["']/,
    why: "These libraries can revive functions: untrusted input becomes code execution.", fix: "Use JSON." }),

  // Crypto, tokens, TLS
  rule({ id: "tls-verify-off", severity: "high", confidence: "high", title: "TLS certificate checks turned off", files: SERVER,
    unless: /^\s*(?:\/\/|#|\*)/,
    re: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|\bverify\s*=\s*False\b|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0)|ssl\._create_unverified_context|VERIFY_NONE/,
    why: "Anyone on the network path can read and change the traffic (man-in-the-middle).", fix: "Keep verification on; for internal CAs, pass the CA bundle instead." }),
  rule({ id: "jwt-alg-none", severity: "critical", confidence: "high", title: "JWT accepts the `none` algorithm or skips verification", files: SERVER,
    re: /algorithms?\s*[:=]\s*\[?[^\]\n]*["']none["']|verify_signature["']?\s*:\s*False|\bverify\s*=\s*False[^\n]*jwt|jwt\.decode\([^)]*verify\s*=\s*False|ignoreExpiration\s*:\s*true/i,
    why: "Anyone can forge a token and log in as anyone.", fix: "Verify with a fixed algorithm list (e.g. `['HS256']`/`['RS256']`) and keep expiry checks." }),
  rule({ id: "jwt-decode-auth", severity: "medium", confidence: "low", title: "jwt.decode() used where verify() may be needed", files: JS,
    re: /\bjwt\.decode\s*\(/,
    why: "jsonwebtoken's decode() does not check the signature; using it for auth trusts any token.", fix: "Use `jwt.verify(token, key, { algorithms: [...] })` for anything that grants access." }),
  rule({ id: "weak-secret", severity: "high", confidence: "high", title: "Guessable signing secret", files: SERVER,
    re: /\b(?:secret|sessionSecret|session_secret|SECRET_KEY|JWT_SECRET|jwtSecret|jwt_secret|cookieSecret|APP_KEY)\b["']?\s*[:=]\s*["'](?:secret|changeme|change[-_ ]?me|keyboard cat|mysecret|my[-_ ]?secret|your[-_ ]?secret[-_ \w]*|supersecret|super[-_ ]?secret|dev|development|test|123456\d*|password|default|s3cr3t|shhh+|jwtsecret|django-insecure-[^"']*)["']/i,
    why: "Anyone who guesses it can forge sessions or tokens.", fix: "Generate 32+ random bytes, keep it in an environment variable, rotate it." }),
  rule({ id: "weak-password-hash", severity: "high", title: "Passwords hashed with a fast hash", files: SERVER,
    re: /\b(?:md5|sha1|sha256|sha512)\b[^;\n]{0,60}\b(?:password|passwd|pwd)\b|\b(?:password|passwd|pwd)\b[^;\n]{0,60}\b(?:md5|sha1|sha256|sha512|createHash)\b/i, unless: /bcrypt|argon2|scrypt|pbkdf2|password_hash|check_password|make_password/i,
    why: "Fast hashes are cracked by the billion per second once the database leaks.", fix: "Use argon2id, bcrypt or scrypt (password_hash in PHP)." }),
  rule({ id: "insecure-random", severity: "medium", title: "Math.random / random used for a secret value", files: SERVER,
    re: /Math\.random\s*\(\s*\)[^;\n]*\b(?:token|secret|password|otp|nonce|salt|session|reset|invite|api[_-]?key|code)\b|\b(?:token|secret|password|otp|nonce|salt|session|reset|invite)\w*\s*[:=][^;\n]*(?:Math\.random|\brandom\.(?:random|randint|choice|choices|randrange)\b|\bmt_rand\b|\brand\s*\()/i,
    why: "These generators are predictable; tokens made with them can be guessed.", fix: "Use crypto.randomUUID / crypto.getRandomValues, `secrets` in Python, random_bytes in PHP." }),
  rule({ id: "weak-cipher", severity: "medium", title: "Weak or deprecated encryption", files: SERVER,
    re: /createCipher\s*\(|\b(?:DES|RC4|RC2|Blowfish)\b|AES\.MODE_ECB|["']aes-\d+-ecb["']|ECB\b[^\n]*Cipher|Cipher\.getInstance\(\s*["']AES["']\s*\)/,
    why: "Broken ciphers or ECB mode leak patterns or can be decrypted.", fix: "Use AES-256-GCM (or libsodium) with a random IV per message." }),

  // Web configuration in code
  rule({ id: "cors-credentials-any", severity: "high", title: "CORS allows any origin with credentials", files: SERVER,
    re: /origin\s*:\s*(?:true|["']\*["']|\(\s*\w*\s*,\s*\w+\s*\)\s*=>\s*\w+\(\s*null\s*,\s*true\s*\))[^}\n]*credentials\s*:\s*true|credentials\s*:\s*true[^}\n]*origin\s*:\s*(?:true|["']\*["'])|Access-Control-Allow-Origin["']?\s*[,:]\s*(?:req|request)\.headers?(?:\.origin|\[["']origin["']\]|\.get\(["']origin)|supports_credentials\s*=\s*True[^\n]*origins\s*=\s*["']\*["']|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|CORS_ORIGIN_ALLOW_ALL\s*=\s*True/,
    why: "Any website a user visits can call your API as that user and read the answers.", fix: "List the exact origins that may call the API." }),
  rule({ id: "debug-enabled", severity: "high", title: "Debug mode on", files: /\.py$/i,
    re: /\bapp\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True\b|DEBUG_PROPAGATE_EXCEPTIONS\s*=\s*True/,
    why: "Debug pages leak code, settings and secrets; the Werkzeug debugger runs code from the browser.", fix: "Drive it from an environment variable that is off in production." }),
  rule({ id: "cookie-flags-off", severity: "medium", title: "Session cookie without HttpOnly or Secure", files: SERVER,
    re: /\bhttpOnly\s*:\s*false|\bhttponly\s*=\s*False|SESSION_COOKIE_HTTPONLY\s*=\s*False|SESSION_COOKIE_SECURE\s*=\s*False|CSRF_COOKIE_SECURE\s*=\s*False|session\.cookie_httponly\s*=\s*0/,
    why: "Without HttpOnly, any XSS steals the session; without Secure, it travels over plain HTTP.", fix: "Set HttpOnly, Secure and SameSite=Lax (or Strict) on session cookies." }),
  rule({ id: "csrf-disabled", severity: "medium", title: "CSRF protection disabled", files: SERVER, perFile: true,
    re: /@csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False|csrf\(\)\.disable|\.csrf\(\s*\w*\s*->\s*\w+\.disable\(\)\)|protect_from_forgery\s+with:\s*:null_session|skip_before_action\s+:verify_authenticity_token/,
    why: "With cookie sessions, another site can submit forms as your user.", fix: "Keep CSRF on for cookie-authenticated routes; exempt only token-authenticated APIs or signed webhooks." }),
  rule({ id: "mass-assignment", severity: "medium", title: "Whole request body written to the database", files: JS,
    re: new RegExp(String.raw`\.(?:create|update|insert|insertOne|insertMany|updateOne|findOneAndUpdate|findByIdAndUpdate|upsert|build|save|set)\s*\(\s*(?:[^,()]+,\s*)?(?:${USER_JS.replace("(?:query|body|params|headers|cookies|url|path|search)", "body")})\s*\)|\bdata\s*:\s*(?:req|request)\.body\b|Object\.assign\(\s*\w+\s*,\s*(?:req|request)\.body\s*\)`),
    why: "Users can set fields you did not mean to expose (`role: \"admin\"`, `ownerId`, `price`).", fix: "Pick the allowed fields explicitly (or validate with a schema that strips the rest)." }),
  rule({ id: "secret-in-client-env", severity: "high", confidence: "high", title: "Secret exposed through a public env prefix", files: ANY,
    re: /\b(?:NEXT_PUBLIC|VITE|PUBLIC|EXPO_PUBLIC|REACT_APP|NUXT_PUBLIC|GATSBY|SVELTEKIT_PUBLIC)_\w*(?:SERVICE_ROLE|SECRET|PRIVATE|ADMIN_KEY|PASSWORD|DB_URL|DATABASE_URL)\w*/,
    why: "Variables with these prefixes are bundled into the JavaScript every visitor downloads.", fix: "Use the value only on the server (API route, server action, edge function) and rotate it." }),
  rule({ id: "firebase-open-rules", severity: "critical", confidence: "high", title: "Firebase rules allow anyone", files: /(\.rules|rules\.json)$/i,
    re: /allow\s+(?:read|write|create|update|delete|get|list)(?:\s*,\s*\w+)*\s*:\s*if\s+true\b|["']\.(?:read|write)["']\s*:\s*(?:true|["']true["'])/,
    why: "Anyone with your public config can read or overwrite the whole database.", fix: "Require `request.auth != null` and check ownership (`request.auth.uid == resource.data.owner`)." }),
  rule({ id: "zip-slip", severity: "medium", title: "Archive extracted without checking entry paths", files: SERVER,
    re: /\.extractall\s*\((?![^)]*filter\s*=)|\.extractAllTo(?:Async)?\s*\(|\btar\.x\s*\(\s*\{(?![^}]*strict)|unzipper\.Extract\s*\(/,
    why: "Entries named `../../x` are written outside the target folder (zip slip).", fix: "Python 3.12+: `extractall(path, filter=\"data\")`; elsewhere check each entry's resolved path stays inside the folder." }),
  rule({ id: "xxe", severity: "high", title: "XML parser resolves external entities", files: SERVER,
    re: /resolve_entities\s*=\s*True|\bnoent\s*:\s*true|libxml_disable_entity_loader\s*\(\s*false|XMLParser\([^)]*load_dtd\s*=\s*True|FEATURE_EXTERNAL_GENERAL_ENTITIES[^\n]*true/,
    why: "A crafted XML file can read local files or call internal URLs (XXE).", fix: "Disable entity resolution and DTD loading; in Python use defusedxml." }),
  rule({ id: "postmessage-no-origin", severity: "medium", confidence: "low", title: "message listener (check that it verifies event.origin)", files: JS,
    // A BroadcastChannel only carries messages from the same origin.
    re: /addEventListener\(\s*["']message["']\s*,|\bonmessage\s*=/, skip: /(^|\/)(?:sw|service-?worker)\.[jt]s$|\.worker\.[jt]s$|(^|\/)workers?\//i,
    // The handler is often a named function further down: the file reads the sender's origin somewhere.
    unlessFile: /\b(?:event|evt|ev|e|msg|message|m)\??\.origin\b|\(\s*\{[^})]*\borigin\b[^})]*\}\s*(?::[^)]*)?\)\s*(?:=>|\{)/,
    unless: /origin|\bself\.(?:addEventListener|onmessage)|^\s*onmessage\s*=|[Ww]orker\w*(?:\.\w+)*\.(?:addEventListener|onmessage)|[Cc]hannel\??\.(?:addEventListener|onmessage)|\b(?:worker|port|socket|ws|eventSource|es)\w*\??\.(?:addEventListener|onmessage)/i,
    why: "Any page that can open or frame yours can send it messages; without an origin check they are trusted.", fix: "Compare `event.origin` to an exact allow-list before acting on the data." }),
  rule({ id: "prototype-pollution", severity: "medium", title: "Deep merge of request data", files: JS,
    re: new RegExp(String.raw`\b(?:merge|mergeWith|defaultsDeep|extend|deepmerge|set|setWith)\s*\([^;\n]*${USER_JS}`), unless: /Object\.create\(null\)|hasOwn|__proto__/,
    why: "Keys like `__proto__` or `constructor.prototype` in the body change every object in the app (prototype pollution).", fix: "Validate the shape with a schema first, or use a merge that blocks __proto__/constructor." }),
  rule({ id: "remote-code-model", severity: "high", title: "Model loaded with remote code enabled", files: PY,
    re: /trust_remote_code\s*=\s*True/,
    why: "The model repository's Python code runs on your machine when it loads.", fix: "Use models that do not need it, or pin a reviewed revision (`revision=\"<commit>\"`)." }),
  rule({ id: "llm-output-exec", severity: "high", confidence: "low", title: "Model output passed to eval, exec or a shell", files: SERVER,
    re: /\b(?:eval|exec|execSync|Function|subprocess\.\w+|os\.system)\s*\([^;\n]*\b(?:completion|response|message|output|answer|result|reply)\w*(?:\.choices|\.content|\.text|\[["']content["']\]|\.output_text)/i,
    why: "Anyone who can influence the prompt (including through documents or web pages the model reads) can run code.", fix: "Never execute model output; map it to a fixed set of allowed actions." }),
  rule({ id: "log-sensitive", severity: "low", confidence: "low", title: "Sensitive value written to logs", files: SERVER,
    re: /\b(?:console\.(?:log|info|debug|warn|error)|logger\.\w+|logging\.\w+|print|log\.\w+)\s*\([^;\n]*\b(?:password|passwd|secret|token|authorization|cookie|card_?number|cvv|ssn|private_?key)\b/i,
    why: "Logs are copied to many places and kept for long; secrets in them leak.", fix: "Log an id or a masked value instead." }),
  rule({ id: "mixed-content", severity: "low", title: "Script or stylesheet loaded over plain HTTP", files: /\.(html?|vue|svelte|astro|jsx|tsx|php|ejs|hbs|erb)$/i,
    re: /<(?:script|link)\b[^>]*\b(?:src|href)\s*=\s*["']http:\/\/(?!localhost|127\.0\.0\.1)/i,
    why: "Anyone on the network can replace it with their own code.", fix: "Use https:// (and Subresource Integrity for third-party CDNs)." }),
];
