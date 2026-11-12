// Vulnerability candidates in Java/Kotlin, C#, Ruby, Go and Rust: the languages AI agents write
// backends in besides JavaScript, Python and PHP (web.mjs). Rule ids match web.mjs so a finding
// reads the same in every language. Candidates: each needs a look at where the input comes from.

const JVM = /\.(java|kt|scala|groovy)$/i;
const CS = /\.(cs|cshtml|razor)$/i;
const RB = /\.(rb|erb|haml|slim)$/i;
const GO = /\.go$/i;
const RS = /\.rs$/i;

const rule = r => ({ category: "web", confidence: "medium", ...r });
const SQL = "Pass values as query parameters (`?`, `@name`, `$1`), never by building the SQL text.";
const SQL_WORD = String.raw`\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b`;
// Request input as each framework spells it.
const JVM_IN = String.raw`(?:request|req|httpRequest|servletRequest)\.(?:getParameter|getHeader|getQueryString|getInputStream|getReader|getCookies|getPathInfo|getRequestURI)\(`;
const CS_IN = String.raw`(?:Request\.(?:Query|Form|Headers|Cookies|RouteValues)|HttpContext\.Request\.\w+)`;
const RB_IN = String.raw`(?:params|request\.(?:params|query_parameters|request_parameters|headers|body))\b`;
const GO_IN = String.raw`(?:r|req|request)\.(?:URL\.Query\(\)\.Get|FormValue|PostFormValue|PathValue|Header\.Get)\(|c\.(?:Query|Param|PostForm|GetHeader|FormValue|QueryParam)\(`;

const GO_SQL_PART = String.raw`(?:strings\.Join\([^()]*\)|[\w.]*[Qq]uote\w*\([^()]*(?:\([^()]*\))?[^()]*\)|[\w.]*\b(?:\w*[Cc]ond\w*|\w*[Ww]here\w*|\w*[Cc]lause\w*|elements|columns|selects|fields|sets|stmt\w*\.SQL|\w*[Tt]able\w*(?:\.Name)?|\w*Collection\.Name|query|dangerous\w+)\b)`;
const GO_SQL_PARTS = new RegExp(String.raw`Sprintf\([^,]*,\s*` + GO_SQL_PART + String.raw`(?:\s*,\s*` + GO_SQL_PART + String.raw`)*\s*\)`);

export const LANG_RULES = [
  // SQL
  rule({ id: "sql-concat", severity: "high", title: "SQL built from strings (Java/Kotlin)", files: JVM, fix: SQL,
    re: new RegExp(String.raw`\.(?:executeQuery|executeUpdate|execute|prepareStatement|createQuery|createNativeQuery|createSQLQuery|queryForList|queryForObject|queryForMap|query|update|addBatch)\s*\(\s*(?:"[^"\n]*${SQL_WORD}[^"\n]*"\s*\+|"[^"\n]*${SQL_WORD}[^"\n]*\$\{?[A-Za-z_]|String\.format\(\s*"[^"\n]*${SQL_WORD}[^"\n]*%s)`, "i"),
    why: "Values pasted into SQL text let an attacker change the query (SQL injection)." }),
  rule({ id: "sql-concat", severity: "high", title: "SQL built from strings (C#)", files: CS, fix: "Use SqlParameter, Dapper parameters, or EF Core's FromSqlInterpolated / FromSql, which turn {values} into parameters.",
    re: new RegExp(String.raw`(?:new\s+(?:Sql|Npgsql|MySql|Sqlite|Oracle)Command|\.(?:FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync|Query|QueryAsync|QueryFirst\w*|Execute|ExecuteAsync|ExecuteScalar\w*))\s*(?:<[^>]*>)?\(\s*(?:\$"[^"\n]*${SQL_WORD}[^"\n]*\{|"[^"\n]*${SQL_WORD}[^"\n]*"\s*\+|string\.Format\()`, "i"),
    why: "Values pasted into SQL text let an attacker change the query (SQL injection)." }),
  rule({ id: "sql-concat", severity: "high", title: "SQL built with string interpolation (Ruby)", files: RB, fix: "Use placeholders: `where(\"name = ?\", name)` or a hash: `where(name: name)`.",
    skip: /(^|\/)db\/(?:post_)?migrate\//,
    re: /\.(?:find_by_sql|count_by_sql|execute|exec_query|select_all|select_value|select_values|select_rows)\s*\(?\s*"[^"\n]*#\{|\.(?:where|order|group|having|joins|pluck|from|update_all|delete_all|reorder|lock)\s*\(?\s*"[^"\n]*(?:[=<>]|\b(?:LIKE|IN|AND|OR|ASC|DESC|IS|BETWEEN|SELECT|FROM)\b)[^"\n]*#\{/i,
    why: "Interpolated SQL is injectable whenever the value comes from a request." }),
  rule({ id: "sql-concat", severity: "high", title: "SQL built with format! (Rust)", files: RS, fix: "Use bound parameters (`sqlx::query(\"... $1\").bind(v)`, diesel's DSL).",
    re: new RegExp(String.raw`(?:query|query_as|query_scalar|execute|sql_query|prepare|query_row|query_map)\s*(?:::<[^>]*>)?\(\s*&?format!\(\s*"[^"\n]*${SQL_WORD}`, "i"),
    why: "Formatted SQL is injectable." }),
  rule({ id: "sql-concat", severity: "high", title: "SQL text built with fmt.Sprintf (Go)", files: GO, fix: "Pass values as query arguments (`db.Query(sql, a, b)`).",
    re: new RegExp(String.raw`fmt\.Sprintf\(\s*["\x60][^"\x60\n]*${SQL_WORD}[^"\x60\n]*%[sv]`, "i"),
    // Every argument is a clause, a list of names or a quoted identifier: a query builder at work.
    unless: GO_SQL_PARTS,
    why: "Formatted SQL is injectable whenever a value comes from a user." }),
  rule({ id: "sql-fragments", severity: "low", title: "SQL assembled from fragments (Go)", files: GO, fix: "Check how each fragment is built; values belong in the query arguments.",
    re: new RegExp(String.raw`fmt\.Sprintf\(\s*["\x60][^"\x60\n]*${SQL_WORD}[^"\x60\n]*%[sv][^"\x60\n]*["\x60]\s*,\s*` + GO_SQL_PART + String.raw`(?:\s*,\s*` + GO_SQL_PART + String.raw`)*\s*\)`, "i"),
    why: "Clauses, lists of names and quoted identifiers are formatted into the query text. That is safe when each is made of names and placeholders, and injectable if one carries a value." }),

  // Commands
  rule({ id: "cmd-injection", severity: "high", title: "Shell command built from strings (Java/Kotlin)", files: JVM, fix: "Run the program directly with a fixed argument list; never through `sh -c` with joined text.",
    re: /(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(\s*(?:"[^"\n]*"\s*\+|[^)\n]*"(?:sh|bash|cmd(?:\.exe)?|powershell)"\s*,\s*"(?:-c|\/c|-Command)"\s*,\s*(?!")[^)\n]+)/,
    why: "Text joined into a shell command can carry extra commands (command injection)." }),
  rule({ id: "cmd-injection", severity: "high", title: "Shell command built from strings (C#)", files: CS, fix: "Start the program directly and pass arguments with ArgumentList, not through cmd /c or a joined string.",
    re: /Process\.Start\(\s*"(?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|bash|sh)"\s*,\s*(?:\$"|"[^"\n]*"\s*\+)|Arguments\s*=\s*\$"[^"\n]*(?:\/c|-c|-Command)\b[^"\n]*\{/i,
    why: "Text joined into a shell command can carry extra commands (command injection)." }),
  rule({ id: "cmd-injection", severity: "critical", confidence: "high", title: "Request data in a shell command (Ruby)", files: RB, fix: "Pass arguments as an array: `system(\"convert\", path)`; never interpolate into a command string.",
    re: new RegExp(String.raw`(?:\b(?:system|exec|spawn|IO\.popen|Open3\.\w+)\s*\(?\s*"[^"\n]*#\{[^}]*${RB_IN}|^[^"'\x60\n]*\x60[^\x60\n]*#\{[^}]*${RB_IN}|%x[({][^)}\n]*#\{[^}]*${RB_IN})`),
    why: "Remote command execution." }),
  rule({ id: "cmd-injection", severity: "high", title: "Shell command built from strings (Ruby)", files: RB, fix: "Pass arguments as an array: `system(\"convert\", path)`.",
    re: /\b(?:system|exec|spawn|IO\.popen|Open3\.\w+)\s*\(?\s*"[^"\n]*#\{|%x[({][^)}\n]*#\{|^[^"'`\n]*`[^`\n]*#\{/,
    why: "Interpolated shell commands are injectable whenever a piece comes from a user." }),
  rule({ id: "cmd-injection", severity: "high", title: "Shell command built from strings (Go)", files: GO, fix: "Call exec.Command with the program and a fixed argument list, without sh -c.",
    re: /exec\.Command(?:Context)?\(\s*(?:ctx\s*,\s*)?"(?:sh|bash|cmd|powershell|pwsh)"\s*,\s*"(?:-c|\/c|-Command)"\s*,\s*(?:fmt\.Sprintf|[^)\n]*\+)/,
    why: "Text joined into a shell command can carry extra commands (command injection)." }),

  // Deserialisation and code evaluation
  rule({ id: "deserialize-unsafe", severity: "high", title: "Deserialiser that can build any type (Java)", files: JVM, fix: "Use JSON with fixed types; for Java serialisation set an ObjectInputFilter allow-list.",
    re: /\.(?:enableDefaultTyping|activateDefaultTyping)\s*\(|new\s+XMLDecoder\s*\(|new\s+Yaml\s*\(\s*\)\s*\.load\s*\(|\bxstream\.fromXML\s*\(|new\s+ObjectInputStream\s*\([^)]*(?:getInputStream|request|socket)/i,
    why: "Untrusted input given to these turns into code execution through gadget classes." }),
  rule({ id: "deserialize-unsafe", severity: "high", title: "Deserialiser that can build any type (.NET)", files: CS, fix: "Use System.Text.Json with fixed types; never BinaryFormatter, and keep Json.NET TypeNameHandling at None.",
    re: /new\s+(?:BinaryFormatter|NetDataContractSerializer|LosFormatter|SoapFormatter|ObjectStateFormatter)\s*\(|TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)|new\s+JavaScriptSerializer\s*\(\s*new\s+SimpleTypeResolver/,
    why: "These read type names from the data; a crafted payload runs code on the server." }),
  rule({ id: "deserialize-unsafe", severity: "high", title: "Unsafe deserialisation (Ruby)", files: RB, fix: "Use JSON, or YAML.safe_load with permitted_classes.",
    re: /\bMarshal\.load\s*\(|\bYAML\.unsafe_load\s*\(|\bOj\.load\s*\([^)\n]*mode:\s*:object|\bPsych\.unsafe_load\s*\(/,
    why: "Marshal and unsafe YAML can instantiate arbitrary objects: untrusted input becomes code execution." }),
  rule({ id: "code-eval-input", severity: "critical", confidence: "high", title: "Request data chooses code to run (Ruby)", files: RB, fix: "Map input to an allow-list of methods or classes.",
    re: new RegExp(String.raw`\b(?:eval|instance_eval|class_eval|module_eval)\s*\(?\s*${RB_IN}|\.(?:send|public_send|__send__)\s*\(\s*${RB_IN}|${RB_IN}\[[^\]]+\]\s*\.(?:safe_)?constantize\b|render\s*\(?\s*inline:\s*${RB_IN}`),
    why: "Calling methods or classes named by the request lets an attacker run code." }),
  rule({ id: "code-eval-input", severity: "high", title: "Expression or JNDI lookup on dynamic input (Java)", files: JVM, fix: "Never evaluate user text as SpEL/OGNL/script; never pass it to JNDI lookups.",
    re: /\.parseExpression\s*\(\s*(?!")[^)\n]+\)|new\s+InitialContext\s*\(\s*\)\s*\.lookup\s*\(\s*(?!")|ScriptEngine[^\n]*\.eval\s*\(\s*(?!")/,
    why: "Expression languages and JNDI lookups on attacker text are classic remote-code-execution paths (Spring4Shell, Log4Shell)." }),

  // TLS, XML, crypto
  rule({ id: "tls-verify-off", severity: "high", confidence: "high", title: "Certificate checks turned off", files: /\.(java|kt|scala|groovy|cs|go|rs)$/i, unless: /^\s*(?:\/\/|\*)/, fix: "Remove the override; trust a specific CA or certificate instead if you need a private one.",
    re: /InsecureSkipVerify\s*:\s*true|danger_accept_invalid_(?:certs|hostnames)\s*\(\s*true|\.dangerous\(\)\s*\.set_certificate_verifier|(?:Server|ServerCertificateCustom)(?:Certificate)?ValidationCallback\s*=\s*[^;\n]*=>\s*true|DangerousAcceptAnyServerCertificateValidator|NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|HostnameVerifier[^\n]*->\s*true|checkServerTrusted\s*\([^)]*\)\s*(?:\{\s*\}|=\s*Unit|\{\s*return;?\s*\})|verify\s*\(\s*String\s+\w+\s*,\s*SSLSession\s+\w+\s*\)\s*\{\s*return\s+true/,
    why: "Anyone on the network path can read and change the traffic (man in the middle)." }),
  rule({ id: "xxe", severity: "high", title: "XML parser resolves external entities (.NET)", files: CS, fix: "Leave DtdProcessing at Prohibit and XmlResolver at null.",
    re: /DtdProcessing\s*=\s*DtdProcessing\.Parse|XmlResolver\s*=\s*new\s+XmlUrlResolver/, unlessFile: /XmlResolver\s*=\s*null/,
    why: "A crafted XML file can read local files or call internal URLs (XXE)." }),

  // Paths, URLs, output
  rule({ id: "path-traversal", severity: "high", title: "File path taken from the request", files: /\.(java|kt|scala|cs|go)$/i, fix: "Map the input to an allow-list, or resolve the path and check it stays inside the base folder.",
    re: new RegExp(String.raw`(?:new\s+File|Paths\.get|Path\.of|Files\.\w+|Path\.Combine|File\.(?:ReadAll\w+|Open\w*|Delete|WriteAll\w+)|filepath\.Join|os\.(?:Open|ReadFile|Create|Remove)|http\.ServeFile)\s*\([^\n]*(?:${JVM_IN}|${CS_IN}|${GO_IN})`),
    why: "`../` in the value reads or writes files outside the intended folder." }),
  rule({ id: "ssrf", severity: "high", title: "Server fetches a URL from the request (SSRF)", files: /\.(java|kt|scala|cs|go|rb)$/i, fix: "Allow-list hosts, block private and link-local addresses, and do not follow redirects blindly.",
    re: new RegExp(String.raw`(?:new\s+URL|URI\.create|RestTemplate\(\)\.\w+|restTemplate\.\w+|webClient\.\w+\(\)\.uri|HttpClient\(\)\.\w+Async|\.GetAsync|\.GetStringAsync|http\.(?:Get|Post|Head)|http\.NewRequest\w*|Net::HTTP\.get|URI\.open|HTTParty\.\w+|Faraday\.\w+|RestClient\.\w+)\s*\([^\n]*(?:${JVM_IN}|${CS_IN}|${GO_IN}|${RB_IN}\[)`),
    why: "An attacker can make your server call internal addresses (cloud metadata, localhost admin panels, the private network)." }),
  rule({ id: "open-redirect", severity: "medium", title: "Redirect to an address from the request", files: /\.(java|kt|scala|cs|rb|go)$/i, fix: "Redirect only to relative paths or an allow-list of hosts.",
    re: new RegExp(String.raw`(?:sendRedirect|redirect_to|Redirect|http\.Redirect)\s*\(?\s*(?:[^\n]*(?:${JVM_IN}|${CS_IN}|${GO_IN})|${RB_IN}\[|"redirect:"\s*\+)`),
    unless: /LocalRedirect|IsLocalUrl|allow_other_host:\s*false|url_from\(/,
    why: "Attackers use your domain to send people to phishing pages." }),
  rule({ id: "xss-framework-raw", severity: "medium", perFile: true, title: "Unescaped output in a server template", files: /\.(cshtml|razor|erb|haml|slim|go)$/i, fix: "Let the template escape it; sanitise first if HTML is really needed.",
    re: new RegExp(String.raw`@Html\.Raw\s*\(|<%==|\braw\s*\(?\s*${RB_IN}|${RB_IN}\[[^\]]+\]\.html_safe|template\.HTML\s*\(\s*(?:${GO_IN})`),
    why: "Values written without escaping can carry script (XSS)." }),
  rule({ id: "csrf-disabled", severity: "medium", title: "CSRF protection turned off", files: /\.(java|kt|cs|rb)$/i, perFile: true, fix: "Keep CSRF protection on for cookie-authenticated endpoints.",
    re: /\.csrf\(\s*\)\s*\.disable\(\)|\.csrf\s*\{\s*(?:it\.)?disable\(\)|csrf\(\s*(?:AbstractHttpConfigurer::disable|csrf\s*->\s*csrf\.disable\(\))|IgnoreAntiforgeryToken|skip_before_action\s+:verify_authenticity_token|protect_from_forgery\s+with:\s*:null_session/,
    why: "Other sites can submit forms as your logged-in users." }),
  rule({ id: "mass-assignment", severity: "high", title: "Every request field allowed into the model", files: RB, fix: "List the permitted fields: `params.require(:user).permit(:name, :email)`.",
    re: /params(?:\.require\([^)]*\))?\.permit!/,
    why: "A request can set fields it should never touch (role, is_admin, owner_id)." }),
];
