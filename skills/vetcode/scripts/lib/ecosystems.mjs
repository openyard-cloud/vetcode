// Code that runs on its own while a project is built or installed, outside npm and PyPI:
// Rust build scripts and proc macros, Go generate directives and init functions, Ruby native
// extensions, Composer scripts, MSBuild targets and NuGet scripts, Gradle and Maven builds.
// An agent that clones a repository and runs `cargo build`, `go generate`, `bundle install`,
// `composer install`, `dotnet build` or `./gradlew` runs all of this without asking.
import { lineOf } from "./engine.mjs";

const rule = r => ({ category: "supply-chain", confidence: "medium",
  fix: "Read what it runs before building or installing. If it downloads or launches something, or touches your home folder, do not build it on a machine with credentials.", ...r });

// What turns build-time code from busy into dangerous.
const DOWNLOAD = /\b(?:curl|wget|Invoke-WebRequest|iwr|irm|Invoke-RestMethod|certutil\s+-urlcache|bitsadmin)\b|DownloadString|DownloadFile|https?:\/\/(?!(?:www\.)?(?:github\.com\/[\w.-]+\/[\w.-]+\/(?:releases|archive)|services\.gradle\.org|repo\.maven\.apache\.org|repo1\.maven\.org|plugins\.gradle\.org|nuget\.org|api\.nuget\.org|crates\.io|static\.crates\.io|rubygems\.org|packagist\.org|proxy\.golang\.org|go\.dev|golang\.org|schemas\.microsoft\.com|maven\.apache\.org|www\.w3\.org|json-schema\.org))/i;
const SHELL = /\b(?:sh|bash|zsh)\s+-c\b|\bcmd(?:\.exe)?\s+\/[ck]\b|\bpowershell(?:\.exe)?\b|\bpwsh\b|-(?:enc|EncodedCommand)\b|\|\s*(?:ba)?sh\b|\biex\b|Invoke-Expression|FromBase64String|base64\s+(?:-d|--decode)/i;
const SECRETS = /\.ssh\b|\.aws\b|\.npmrc|\.git-credentials|\.docker\/config|\.kube\/config|id_rsa|id_ed25519|Login Data|wallet|keychain|\b(?:HOME|USERPROFILE|APPDATA)\b|home_dir\s*\(|UserHomeDir\s*\(|getProperty\(\s*"user\.home"|Environment\.GetFolderPath/i;

const hit = (text, m, ev) => [{ line: lineOf(text, m.index), evidence: (ev || m[0]).trim().slice(0, 160) }];
const first = (text, ...res) => { for (const re of res) { const m = re.exec(text); if (m) return m; } return null; };

export const ECOSYSTEM_FILE_RULES = [
  // Rust: build.rs runs on `cargo build`; proc macros run inside the compiler and the editor.
  { ...rule({ id: "rust-build-script", severity: "high", title: "Rust build script reaches out or reads your secrets",
      why: "build.rs runs on every `cargo build` and `cargo check`, with your user's rights. Build scripts compile C code and generate files; one that downloads, runs a shell or reads your home folder is doing something else." }),
    files: /(^|\/)build\.rs$/,
    test(text) {
      const net = first(text, /\b(?:reqwest|ureq|attohttpc|minreq|hyper)::|TcpStream::connect|UdpSocket::bind|Command::new\(\s*"(?:curl|wget|powershell|pwsh)"/);
      const risky = first(text, SECRETS, /Command::new\(\s*"(?:sh|bash|cmd|powershell)"\s*\)[\s\S]{0,120}\.arg\(\s*"(?:-c|\/C)"/, /base64::|from_base64|decode\(/);
      if (net && risky) return hit(text, net, `${net[0]} + ${risky[0]}`);
      return risky && /\.ssh\b|id_rsa|id_ed25519|\.aws\b|wallet|Login Data/.test(risky[0]) ? hit(text, risky) : [];
    } },
  { ...rule({ id: "rust-build-script-network", severity: "medium", title: "Rust build script downloads at build time",
      why: "Some -sys crates fetch a prebuilt library; it is still code from the network entering your build, unpinned unless the script checks a hash." }),
    files: /(^|\/)build\.rs$/,
    test(text) { const m = /\b(?:reqwest|ureq|attohttpc|minreq)::|Command::new\(\s*"(?:curl|wget)"/.exec(text); return m && !/sha256|Sha256|checksum|hash/i.test(text) ? hit(text, m) : []; } },
  { ...rule({ id: "rust-proc-macro-side-effects", severity: "high", title: "Procedural macro runs programs or uses the network",
      why: "Proc macros execute inside the compiler and inside rust-analyzer as soon as the project is opened. Generating code needs neither the network nor other programs." }),
    files: /\.rs$/,
    test(text) {
      if (!/#\[proc_macro(?:_derive|_attribute)?\b/.test(text)) return [];
      const m = first(text, /std::process::Command|Command::new\(/, /TcpStream::connect|\b(?:reqwest|ureq)::/, /std::fs::(?:read_to_string|read)\([^)]*(?:home|\.ssh|\.aws|env::var)/);
      return m ? hit(text, m) : [];
    } },

  // Go: go:generate runs arbitrary commands; init() runs on import.
  { ...rule({ id: "go-generate-download", severity: "high", confidence: "high", title: "go:generate downloads or runs a shell",
      why: "`go generate` runs these lines as commands. Code generators are local tools; fetching and piping into a shell is how booby-trapped repositories get a foothold." }),
    files: /\.go$/,
    test(text) { const m = /^\s*\/\/go:generate\s+.*$/m.exec(text); if (!m) return []; for (const g of text.matchAll(/^\s*\/\/go:generate\s+(.*)$/gm)) if (DOWNLOAD.test(g[1]) || SHELL.test(g[1])) return hit(text, g); return []; } },
  { ...rule({ id: "go-init-side-effects", severity: "high", title: "Go init() runs programs or calls the network",
      why: "init() runs as soon as the package is imported, before main and without being called. Libraries use it to register things, not to start programs or phone home." }),
    files: /\.go$/, skip: /(^|\/)(?:main|cmd\/[^/]+\/main)\.go$|_test\.go$/,
    test(text) {
      if (/^package\s+main\b/m.test(text)) return [];
      for (const m of text.matchAll(/^func\s+init\s*\(\s*\)\s*\{([\s\S]*?)^\}/gm)) {
        const body = m[1], bad = /exec\.Command|syscall\.Exec|net\.Dial|http\.(?:Get|Post|NewRequest)|os\.UserHomeDir|os\.Hostname/.exec(body);
        if (bad && (/exec\.Command|syscall\.Exec/.test(body) || /net\.Dial|http\./.test(body) && /os\.(?:UserHomeDir|Hostname|Getenv|Environ)/.test(body))) return [{ line: lineOf(text, m.index), evidence: `init(): ${bad[0]}` }];
      }
      return [];
    } },
  { ...rule({ id: "go-mod-replace-remote", severity: "medium", title: "go.mod swaps a dependency for another module",
      why: "A replace directive pointing at a different repository makes the build use that code instead of the module everyone else gets, without anything visible in the imports." }),
    files: /(^|\/)go\.mod$/,
    test(text) {
      for (const m of text.matchAll(/^\s*(?:replace\s+)?([\w.\-/]+)(?:\s+v[\w.\-+]+)?\s*=>\s*([\w.\-/]+)\s+v[\w.\-+]+/gm)) {
        const [from, to] = [m[1], m[2]], host = s => s.split("/").slice(0, 3).join("/");
        if (!to.startsWith(".") && host(from) !== host(to) && !/^golang\.org\/x\/|^google\.golang\.org\//.test(from)) return hit(text, m);
      }
      return [];
    } },

  // Ruby: a gem's native extension (extconf.rb, mkrf_conf.rb, Rakefile) runs on `gem install`.
  { ...rule({ id: "ruby-extension-script", severity: "high", title: "Gem extension script downloads or runs a shell",
      why: "extconf.rb and friends run during `gem install` / `bundle install`. They configure a C build; downloading or shelling out from there is how malicious gems run code." }),
    files: /(^|\/)(?:extconf|mkrf_conf)\.rb$|(^|\/)ext\/[^/]+\/Rakefile$/,
    test(text) {
      const m = first(text, /Net::HTTP|open-uri|URI\.open|\bopen\(\s*["']https?:/, /(?:system|exec|spawn|`|%x)[^\n]*(?:curl|wget|powershell|bash\s+-c|sh\s+-c|\|\s*sh)/, SECRETS);
      return m ? hit(text, m) : [];
    } },
  { ...rule({ id: "ruby-insecure-source", severity: "medium", title: "Gems fetched over plain HTTP",
      why: "Anyone on the network can swap the gems in transit." }),
    files: /(^|\/)(?:Gemfile|gems\.rb)$/,
    test(text) { const m = /^\s*source\s+["']http:\/\//m.exec(text); return m ? hit(text, m) : []; } },

  // PHP: root composer.json scripts run on `composer install` in a cloned project.
  { ...rule({ id: "composer-script-suspicious", severity: "high", confidence: "high", title: "Composer script downloads, decodes or runs a shell",
      why: "Scripts such as post-install-cmd run on `composer install` in the cloned project, with your user's rights." }),
    files: /(^|\/)composer\.json$/,
    test(text) {
      let j; try { j = JSON.parse(text); } catch { return []; }
      for (const [k, v] of Object.entries(j.scripts || {})) for (const cmd of [].concat(v)) {
        if (typeof cmd === "string" && (DOWNLOAD.test(cmd) || SHELL.test(cmd) || /\beval\b|base64_decode/.test(cmd))) { const i = text.indexOf(JSON.stringify(cmd).slice(1, 30)); return [{ line: i >= 0 ? lineOf(text, i) : 1, evidence: `"${k}": "${cmd.slice(0, 120)}"` }]; }
      }
      return [];
    } },
  { ...rule({ id: "composer-insecure-repository", severity: "medium", title: "Composer repository over plain HTTP",
      why: "Packages from it can be swapped in transit." }),
    files: /(^|\/)composer\.json$/,
    test(text) { const m = /"url"\s*:\s*"http:\/\/(?!localhost|127\.0\.0\.1)/.exec(text); return m && /"secure-http"\s*:\s*false|"repositories"/.test(text) ? hit(text, m) : []; } },

  // .NET: MSBuild targets run on build and on opening the project in an IDE; NuGet scripts run on install.
  { ...rule({ id: "msbuild-exec-suspicious", severity: "critical", confidence: "high", title: "Project file runs a download or a hidden command at build time",
      why: "Exec tasks and pre/post-build events run on `dotnet build` and when the project is opened in Visual Studio. In 2021 attackers sent security researchers Visual Studio projects whose build event ran an encoded PowerShell backdoor." }),
    files: /\.(?:csproj|vbproj|fsproj|vcxproj|proj|props|targets)$|(^|\/)Directory\.Build\.(?:props|targets)$/i,
    test(text) {
      for (const m of text.matchAll(/<Exec\b[^>]*\bCommand\s*=\s*"([^"]*)"|<(Pre|Post)BuildEvent>([\s\S]*?)<\/\2BuildEvent>/g)) {
        const cmd = (m[1] ?? m[3] ?? "").replace(/&quot;/g, '"').replace(/&amp;/g, "&");
        if (DOWNLOAD.test(cmd) || SHELL.test(cmd) && /-(?:enc|EncodedCommand)\b|FromBase64String|iex\b|Invoke-Expression|\|\s*(?:ba)?sh\b|-w(?:indowstyle)?\s+hidden/i.test(cmd)) return hit(text, m, cmd);
      }
      return [];
    } },
  { ...rule({ id: "msbuild-inline-task", severity: "medium", title: "Project file compiles and runs inline code at build time",
      why: "Inline MSBuild tasks are C# that runs during the build. Legitimate projects rarely need them; malicious packages and projects have used them to run payloads." }),
    files: /\.(?:csproj|vbproj|fsproj|vcxproj|proj|props|targets)$/i,
    test(text) { const m = /<UsingTask\b[^>]*TaskFactory\s*=\s*"(?:RoslynCodeTaskFactory|CodeTaskFactory)"/.exec(text); return m ? hit(text, m) : []; } },
  { ...rule({ id: "nuget-install-script", severity: "high", title: "NuGet install script downloads or runs hidden commands",
      why: "install.ps1 and init.ps1 run inside Visual Studio when the package is installed." }),
    files: /(^|\/)tools\/(?:install|init)\.ps1$/i,
    test(text) { const m = first(text, DOWNLOAD, /-(?:enc|EncodedCommand)\b|FromBase64String|Invoke-Expression|\biex\b|Start-Process/i); return m ? hit(text, m) : []; } },

  // JVM: Gradle scripts run on every build; the wrapper downloads Gradle itself.
  { ...rule({ id: "gradle-build-exec", severity: "high", title: "Gradle build downloads or runs a shell",
      why: "build.gradle and settings.gradle are code that runs on every `./gradlew` and when an IDE imports the project." }),
    files: /(^|\/)(?:build|settings|init)\.gradle(?:\.kts)?$|\.gradle$/,
    test(text) {
      for (const m of text.matchAll(/(?:\bexec\s*\{|\bcommandLine\s*\(?|\.execute\(\)|Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\()[^\n]*/g)) {
        const around = text.slice(m.index, m.index + 400);
        if (DOWNLOAD.test(around) && /curl|wget|iwr|Invoke-WebRequest|powershell|\|\s*(?:ba)?sh/i.test(around) || /-(?:enc|EncodedCommand)\b|FromBase64String|base64\s+-d/i.test(around)) return hit(text, m);
      }
      return [];
    } },
  { ...rule({ id: "gradle-wrapper-source", severity: "high", title: "Gradle wrapper downloads Gradle from an unusual place",
      why: "`./gradlew` downloads and runs whatever distributionUrl points at. A swapped URL runs someone else's build tool on your machine." }),
    files: /(^|\/)gradle-wrapper\.properties$/,
    test(text) {
      const m = /^\s*distributionUrl\s*=\s*(\S+)/m.exec(text);
      if (!m) return [];
      const url = m[1].replace(/\\:/g, ":");
      return /^https:\/\/services\.gradle\.org\/distributions\//.test(url) ? [] : hit(text, m, `distributionUrl=${url}`);
    } },
  { ...rule({ id: "maven-plugin-exec", severity: "high", title: "Maven build runs a download or a shell",
      why: "exec-maven-plugin and maven-antrun-plugin run commands during `mvn` builds." }),
    files: /(^|\/)pom\.xml$/,
    test(text) {
      for (const m of text.matchAll(/<(?:executable|exec\b[^>]*executable\s*=\s*")[^<"]*|<argument>[^<]*<\/argument>|<arg\s+(?:value|line)\s*=\s*"[^"]*"/g)) {
        const around = text.slice(Math.max(0, m.index - 300), m.index + 300);
        if (/exec-maven-plugin|maven-antrun-plugin/.test(text) && (DOWNLOAD.test(around) && /curl|wget|powershell|iwr/i.test(around) || /\|\s*(?:ba)?sh\b|-(?:enc|EncodedCommand)\b|base64\s+-d/.test(around))) return hit(text, m);
      }
      return [];
    } },
  { ...rule({ id: "jvm-insecure-repository", severity: "medium", title: "Build pulls dependencies over plain HTTP",
      why: "Anyone on the network can swap the artifacts in transit." }),
    files: /(^|\/)(?:pom\.xml|settings\.xml|build\.gradle(?:\.kts)?|settings\.gradle(?:\.kts)?)$/,
    test(text) { const m = /<url>\s*http:\/\/(?!localhost|127\.0\.0\.1)[^<]+<\/url>|\burl\s*(?:=|\()\s*(?:uri\()?\s*["']http:\/\/(?!localhost|127\.0\.0\.1)/.exec(text); return m ? hit(text, m) : []; } },
];
