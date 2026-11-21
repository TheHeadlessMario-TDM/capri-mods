"""Checks mods/<folder>/ against the safety rules Capri enforces, so nothing that trips a hard rule gets listed.

    python3 tools/check-mods.py [--all | --changed BASE_SHA | folder ...]
    python3 tools/check-mods.py PARENT COMMIT

The last form reads the mods changed between two git revisions straight from git, without a checkout.

Prints a Markdown report (also appended to $GITHUB_STEP_SUMMARY when set). Exits 1 if any hard failure, else 0.
"""
import io, json, os, posixpath, re, stat, subprocess, sys, urllib.parse, zipfile

here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
root = os.path.join(here, 'mods')
kinds = ('.capri-mod', '.capri-code', '.capri-skin', '.capri-skill', '.capri-plugin')
mb = 1024 * 1024

packs = re.compile(r"FromBase64String|Aes\.|AesManaged|Rijndael|TripleDES|DESCryptoServiceProvider|GZipStream|DeflateStream|BrotliStream")
loads = re.compile(r"Assembly\.Load|AssemblyLoadContext|AppDomain\.CreateDomain|ExecuteAssembly|CreateInstanceAndUnwrap|Reflection\.Emit|DynamicMethod|CompileAssembly|CodeDomProvider|CSharpCodeProvider|CSharpCompilation")

secret = re.compile(r"sk-(?:ant|proj|or-v1|svcacct|admin)-[A-Za-z0-9_-]{16,}|\bgh[pousr]_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}|\bxox[abprse]-[A-Za-z0-9-]{10,}|\bAKIA[0-9A-Z]{16}\b|\bAIza[0-9A-Za-z_-]{30,}|\bglpat-[A-Za-z0-9_-]{16,}|\bhf_[A-Za-z0-9]{20,}\b|\bnpm_[A-Za-z0-9]{20,}\b|\bnvapi-[A-Za-z0-9_-]{16,}|\bgsk_[A-Za-z0-9]{16,}|\bxai-[A-Za-z0-9]{16,}")

fetches = re.compile(r"\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|bitsadmin|start-bitstransfer|certutil|downloadstring|downloadfile|downloaddata|urlopen|urlretrieve)\b|\bnet\.webclient\b|\burllib\.request\b|\brequests\.get\b|\bfetch\s*\(|\bhttps?\.get\s*\(", re.I)
runs = re.compile(r"\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|ksh|fish|python[0-9.]*|py|node|perl|ruby|php|iex|pwsh|powershell)\b|\b(?:iex|invoke-expression)\b|\beval\b|\bexec\s*\(|<\(\s*(?:curl|wget)\b|\bchmod\s+[+0-7ugoa]*x\b|\bstart-process\b|&&\s*\.{0,2}[\\/]", re.I)
unpacks = re.compile(r"\bb64decode\b|\bfrombase64string\b|\bbase64\s+(?:-d|--decode)\b|\batob\s*\(|['\"]base64['\"]\s*\)", re.I)
shell_name = re.compile(r"powershell|pwsh", re.I)
runner_name = re.compile(r"^(npx|bunx|pnpx|uvx)(\.cmd|\.exe)?$", re.I)
version_tail = re.compile(r"^\d+(\.\d+)*([-+][0-9A-Za-z.-]+)?$")
secret_env_name = re.compile(r"(?:^|_)(?:API_?KEYS?|KEYS?|TOKENS?|SECRETS?|PASSWORDS?|PASSWD|PASS|PAT|CREDENTIALS?|COOKIES?)(?:_|$)", re.I)
env_use = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

manifests = ('.claude-plugin/plugin.json', 'plugin.json', 'capri-plugin.json')
server_files = ('.mcp.json', 'mcp.json')
plugin_files = ('plugin.json', 'capri-plugin.json', '.mcp.json', 'mcp.json')
known_permissions = ('network', 'files', 'send', 'pay', 'apps', 'accounts')
starters = ('email', 'notion', 'linear')
good_id = re.compile(r"[a-z0-9][a-z0-9-]{0,47}")
server_shape = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}")
env_shape = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
header_shape = re.compile(r"[A-Za-z0-9-]{1,64}")
builtin_shape = re.compile(r"[a-z0-9][a-z0-9_-]{0,39}")
reserved_headers = ('host', 'content-length', 'content-type', 'accept', 'transfer-encoding', 'connection', 'expect', 'user-agent',
                    'mcp-session-id', 'mcp-protocol-version', 'range', 'if-modified-since', 'date', 'proxy-connection')
setting_use = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-[^}]*)?\}")
own_root = ('CLAUDE_PLUGIN_ROOT', 'CAPRI_PLUGIN_ROOT')
most_servers, most_skills, largest_skill, largest_json = 4, 20, 64 * 1024, 256 * 1024

capri_folder = re.compile(r"(?:AppData|Application Support|\.config)[\\/]+(?:(?:Local|Roaming)[\\/]+)?Capri\b|(?:LOCALAPPDATA|ApplicationData|APPDATA)[^\r\n]{0,40}?[\"'\\/]Capri\b|\bCapriAI_[A-Za-z0-9]+", re.I)
capri_folder_words = "reaches into Capri's own settings folder, where her keys are saved"

code_warnings = (
    ("loads code while it runs", loads),
    ("unpacks hidden text", packs),
    ("unlocks saved secrets", re.compile(r"ProtectedData|CryptUnprotectData|\.dpapi\b")),
    ("calls Windows directly", re.compile(r"DllImport|LibraryImport|Marshal\.|GetProcAddress|VirtualAlloc")),
    ("starts programs", re.compile(r"Process\.Start|ProcessStartInfo|cmd\.exe|powershell")),
    ("uses the network", re.compile(r"HttpClient|WebClient|WebRequest|TcpClient|UdpClient|Socket\(|ClientWebSocket")),
    ("reaches outside her folder", re.compile(r"SpecialFolder|Registry|DriveInfo|GetTempPath|GetEnvironmentVariable")),
    ("reads the keyboard", re.compile(r"GetAsyncKeyState|SetWindowsHookEx|keybd_event|SendKeys")),
    ("changes what her brain is told", re.compile(r"ICapriBrain|ICapriChat|AddContext|AddTool|\.Sending\b|\.Replying\b|ToolUsing|Personality\.(?:Add|Remove|Clear)\b|(?i:system prompt)")),
)

url = re.compile(r"\b(?:https?|wss?|ftp)://([^\s/\\?#\"'<>]+)", re.I)
skipped_hosts = ('localhost', '0.0.0.0', 'schemas.microsoft.com', 'www.w3.org', 'schemas.openxmlformats.org')
base64_run = re.compile(r"[A-Za-z0-9+/=]{800,}")


class Result:
    def __init__(self, folder):
        self.folder = folder
        self.fails = []
        self.warns = []

    def fail(self, rule, why):
        self.fails.append((rule, why))

    def warn(self, text):
        if text not in self.warns:
            self.warns.append(text)


def text_of(data):
    return data.decode('utf-8', 'replace')


def host_list(text):
    found = []
    for match in url.finditer(text):
        host = match.group(1).rsplit('@', 1)[-1]
        host = re.sub(r":\d*$", "", host).lower()
        if host and host not in found and not host.startswith('127.') and host not in skipped_hosts:
            found.append(host)
    return found


def unreadable(text):
    lines = text.splitlines()
    longest = max((len(line) for line in lines), default=0)
    if base64_run.search(text) or longest > 600:
        return True
    if len(text) > 4000:
        return len(lines) <= 1 or longest * 10 >= len(text) * 9 or text.count(' ') * 20 < len(text)
    return False


def check_secrets(result, name, data):
    if secret.search(data.decode('latin-1')):
        result.fail("a key is written into the mod", "secret-shaped text in `" + name + "`")


def check_settings_folder(result, text):
    if capri_folder.search(text):
        result.warn(capri_folder_words)


def check_code(result, name, data):
    if len(data) > mb:
        result.fail("code mod too big", "`" + name + "` is " + str(len(data)) + " bytes, over 1 MB")
    text = text_of(data)
    has_packs, has_loads = packs.search(text), loads.search(text)
    if has_packs and has_loads:
        result.fail("the code you can read isn't the code that would run", "`" + name + "` unpacks text and also loads code")
    for label, pattern in code_warnings:
        if pattern.search(text):
            result.warn(label)
    check_settings_folder(result, text)
    hosts = host_list(text)
    if hosts:
        result.warn("contacts " + ", ".join(hosts))
    if unreadable(text):
        result.warn("code that is hard to read")


def zip_problem(zf, size):
    infos = zf.infolist()
    if size > mb:
        return "zip is over 1 MB"
    if len(infos) > 400:
        return "more than 400 entries"
    if sum(i.file_size for i in infos) > 8 * mb:
        return "unpacks to over 8 MB"
    seen = set()
    for i in infos:
        if i.file_size > 4 * mb:
            return "`" + i.filename + "` is over 4 MB"
        name = i.orig_filename.replace('\\', '/')
        if name.startswith('/') or ':' in name or '\0' in name or '..' in name.split('/'):
            return "unsafe entry name `" + i.orig_filename + "`"
        if stat.S_ISLNK(i.external_attr >> 16):
            return "`" + i.filename + "` is a link, not a file"
        if name.lower() in seen:
            return "`" + i.filename + "` is in it twice"
        seen.add(name.lower())
    return None


def pinned(runner, package):
    if runner.lower().startswith('uvx'):
        return re.search(r"==\d", package) is not None
    at = package.rfind('@')
    return at > 0 and version_tail.match(package[at + 1:]) is not None


def package_of(args):
    for i, arg in enumerate(args):
        if arg in ('--from', '-p', '--package') and i + 1 < len(args):
            return args[i + 1]
        for flag in ('--from=', '--package='):
            if arg.startswith(flag):
                return arg[len(flag):]
    for arg in args:
        if not arg.startswith('-'):
            return arg
    return None


def encoded_powershell(command, line, args):
    if not (re.match(r"^(powershell|pwsh)(\.exe)?$", posixpath.basename(command.replace('\\', '/')), re.I) or shell_name.search(line)):
        return False
    for arg in args:
        arg = arg.strip().lower()
        if len(arg) < 2 or arg[0] not in '-/':
            continue
        word = arg.lstrip('-/')
        if word in ('e', 'ec') or (len(word) >= 2 and 'encodedcommand'.startswith(word)):
            return True
    return False


def check_server(result, name, server):
    if not isinstance(server, dict) or not isinstance(server.get('command'), str):
        return
    command = server['command']
    args = [a if isinstance(a, str) else str(a) for a in server.get('args') or [] if not isinstance(a, (dict, list))]
    line = command + " " + " ".join(args)
    where = "server `" + name + "`"
    if encoded_powershell(command, line, args):
        result.fail("encoded PowerShell", where + " starts PowerShell with an encoded command")
    if fetches.search(line) and runs.search(line):
        result.fail("downloads and runs", where + " downloads something and runs it")
    if unpacks.search(line) and runs.search(line):
        result.fail("unpacks and runs", where + " decodes something hidden and runs it")
    base = posixpath.basename(command.replace('\\', '/'))
    if runner_name.match(base):
        package = package_of(args)
        if package and not pinned(base, package):
            result.fail("unpinned package", where + " runs `" + package + "` without a pinned version, so what runs could change after review")
    values = [command] + args + [server.get('cwd')] + list((server.get('env') or {}).values() if isinstance(server.get('env'), dict) else [])
    for value in values:
        for var in env_use.findall(value if isinstance(value, str) else ''):
            if secret_env_name.search(var):
                result.warn("server `" + name + "` passes `${" + var + "}` from the environment")


def check_plugin(result, name, data):
    size = len(data)
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        result.fail("plug-in isn't a valid zip", "`" + name + "` can't be opened as a zip")
        return
    files, every = {}, []
    with zf:
        problem = zip_problem(zf, size)
        if problem:
            result.fail("plug-in zip limits", "`" + name + "`: " + problem)
            return
        try:
            for info in zf.infolist():
                entry = info.filename.replace('\\', '/')
                every.append(entry)
                if info.is_dir():
                    continue
                data = zf.read(info)
                files[entry] = data
                check_secrets(result, name + ":" + info.filename, data)
                if b'\0' not in data:
                    check_settings_folder(result, text_of(data))
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError, OSError):
            result.fail("plug-in isn't a valid zip", "`" + name + "` has an unreadable entry")
            return
    used = check_plugin_parts(result, name, files, every)
    for entry, data in files.items():
        if entry not in used and posixpath.basename(entry).lower() in plugin_files:
            for server_name, server in (server_map(read_json(data)[0]) or {}).items():
                check_server(result, server_name, server)


class Repeated(ValueError):
    pass


def unique(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise Repeated(key)
        seen[key] = value
    return seen


marks = ((bytes((0, 0, 0xfe, 0xff)), 'utf-32-be'), (bytes((0xff, 0xfe, 0, 0)), 'utf-32-le'), (bytes((0xef, 0xbb, 0xbf)), 'utf-8'),
         (bytes((0xfe, 0xff)), 'utf-16-be'), (bytes((0xff, 0xfe)), 'utf-16-le'))


def plugin_text(data):
    codec = 'utf-8'
    for mark, named in marks:
        if data.startswith(mark):
            data, codec = data[len(mark):], named
            break
    return data.decode(codec, 'replace').lstrip(chr(0xfeff))


def read_json(data):
    if len(data) > largest_json:
        return None, "is over 256 KB"
    try:
        return json.loads(plugin_text(data), strict=False, object_pairs_hook=unique), None
    except Repeated as repeated:
        return None, "names `" + str(repeated.args[0])[:60] + "` twice, so what Capri reads could differ from what was reviewed"
    except (ValueError, RecursionError):
        return None, "isn't valid JSON"


def slug(name):
    made = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip('-')
    if len(made) > 48:
        made = made[:48].rstrip('-')
    return made or 'my-tools'


def has_parts(names, prefix):
    for name in names:
        if name.lower().startswith(prefix.lower()):
            inner = name[len(prefix):].lower()
            if inner in manifests or inner in server_files or inner == 'skill.md' or inner.startswith('skills/'):
                return True
    return False


def plugin_root(names):
    if has_parts(names, ''):
        return ''
    folders = {name.split('/', 1)[0] for name in names if '/' in name}
    loose = any('/' not in name for name in names)
    if not loose and len(folders) == 1:
        folder = next(iter(folders)) + '/'
        if has_parts(names, folder):
            return folder
    return ''


def server_map(source):
    if not isinstance(source, dict):
        return None
    for key in ('mcpServers', 'servers'):
        if isinstance(source.get(key), dict):
            return source[key]
    if source and all(isinstance(one, dict) and (one.get('command') is not None or one.get('url') is not None) for one in source.values()):
        return source
    return None


def text_field(value, key):
    found = value.get(key) if isinstance(value, dict) else None
    return found if isinstance(found, str) else None


def secure(address):
    try:
        parts = urllib.parse.urlsplit(address)
        host = (parts.hostname or '').lower()
        named = parts.username is not None or parts.password is not None
    except ValueError:
        return False
    if len(address) > 2000 or named:
        return False
    return parts.scheme == 'https' and bool(host) or parts.scheme == 'http' and host in ('127.0.0.1', 'localhost', '::1')


def server_source(result, manifest, manifest_name, files, lower, root, used):
    listed = manifest.get('mcpServers') if isinstance(manifest, dict) else None
    found = None
    if isinstance(listed, str):
        others = [one.group(1) for one in setting_use.finditer(listed) if one.group(1) not in own_root]
        if others:
            result.fail("plug-in servers", "`mcpServers` points through `${" + others[0] + "}`, a setting on the PC, so the file Capri reads could change after review")
            return None, None, False
        top = posixpath.normpath('/plugin/' + root)
        full = posixpath.normpath(posixpath.join(top, setting_use.sub(top, listed).replace('\\', '/')))
        found = lower.get(full[len('/plugin/'):].lower()) if full.startswith(top + '/') else None
        if not found:
            result.fail("plug-in servers", "`mcpServers` points at `" + listed[:80] + "`, which isn't in the plug-in")
            return None, None, False
    elif listed is not None:
        return {'mcpServers': listed}, manifest_name, True
    else:
        for one in server_files:
            found = lower.get((root + one).lower())
            if found:
                break
    if not found:
        return None, None, True
    used.add(found)
    source, problem = read_json(files[found])
    if problem:
        result.fail("plug-in JSON", "`" + found + "` " + problem)
        return None, None, False
    return source, found, True


def check_plugin_parts(result, name, files, every):
    lower = {entry.lower(): entry for entry in files}
    root = plugin_root(every)
    used = set()
    manifest, manifest_name = None, None
    for one in manifests:
        found = lower.get((root + one).lower())
        if found:
            manifest_name = found
            used.add(found)
            manifest, problem = read_json(files[found])
            if problem or not isinstance(manifest, dict):
                result.fail("plug-in JSON", "`" + found + "` " + (problem or "has to be a JSON object"))
                return used
            break
    named = text_field(manifest, 'name')
    stem = name[:-len('.capri-plugin')] if name.endswith('.capri-plugin') else name
    plugin_id = slug(named if named is not None else stem)
    if not good_id.fullmatch(plugin_id):
        result.fail("plug-in id", "its name needs letters or numbers in it")
    elif plugin_id != stem:
        result.fail("plug-in file name", "`" + name + "` has to be called `" + plugin_id + ".capri-plugin`, after its plug-in's name, so Capri knows when it's installed and finds its updates. On the Submit a mod form, that's the Mod id `" + plugin_id + "`")
    if plugin_id in starters:
        result.fail("plug-in id", "`" + plugin_id + "` is one of her starter plug-ins, so installing it would replace hers")
    capri = manifest.get('capri') if isinstance(manifest, dict) else None
    permissions = capri.get('permissions') if isinstance(capri, dict) else None
    for one in permissions if isinstance(permissions, list) else []:
        if not isinstance(one, str) or one.strip().lower() not in known_permissions:
            result.fail("unknown plug-in permission", "`" + str(one)[:40] + "` isn't one Capri knows. A plug-in can say it uses " + ", ".join(known_permissions))
    source, source_name, fine = server_source(result, manifest, manifest_name, files, lower, root, used)
    if not fine:
        return used
    servers = server_map(source) if source_name else {}
    if servers is None:
        result.fail("plug-in servers", "`" + source_name + "` needs an mcpServers object, like Claude's .mcp.json")
        return used
    usable = 0
    for server_name, server in servers.items():
        command, address = text_field(server, 'command'), text_field(server, 'url')
        kind = (text_field(server, 'type') or ('http' if command is None and address is not None else 'stdio')).lower()
        online, inside = kind in ('http', 'streamable-http', 'sse'), kind == 'capri'
        where = "server `" + str(server_name)[:40] + "`"
        if not online and not inside and (kind != 'stdio' or command is None):
            result.warn("leaves out " + where + ", a kind Capri doesn't use")
            continue
        if usable == most_servers:
            result.fail("plug-in servers", "a plug-in can start up to " + str(most_servers) + " servers")
            break
        if not server_shape.fullmatch(server_name):
            result.fail("plug-in servers", where + " has to be named with letters, numbers, spaces, dots, dashes and underscores")
        if online:
            if address is None or not secure(address):
                result.warn("leaves out " + where + ", at an address that isn't https")
                continue
            headers = server.get('headers')
            if isinstance(headers, dict):
                if len(headers) > 16:
                    result.fail("plug-in servers", where + " can send up to 16 headers")
                if any(not header_shape.fullmatch(header) or header.lower() in reserved_headers or not isinstance(value, str) for header, value in headers.items()):
                    result.fail("plug-in servers", where + "'s headers must be ordinary header names with text values")
        elif inside:
            built = (text_field(server, 'builtin') or '').strip()
            if not builtin_shape.fullmatch(built):
                result.fail("plug-in servers", where + " needs a builtin name, like `mail`")
            else:
                result.warn(where + " uses Capri's own `" + built + "` tools")
        else:
            args = server.get('args')
            if any(value is None or isinstance(value, (dict, list)) for value in (args if isinstance(args, list) else [])):
                result.fail("plug-in servers", where + "'s args must be text")
            env = server.get('env')
            if isinstance(env, dict) and any(not env_shape.fullmatch(key) or not isinstance(value, str) for key, value in env.items()):
                result.fail("plug-in servers", where + "'s env must be names with text values")
            check_server(result, server_name, server)
        usable += 1
    skills = plugin_skills(manifest, files, root, lower)
    if len(skills) > most_skills:
        result.fail("plug-in skills", "a plug-in can have up to " + str(most_skills) + " skills")
    for skill in skills:
        if len(files[skill]) > largest_skill:
            result.fail("plug-in skills", "`" + skill + "` is over 64 KB")
    if usable == 0 and not skills:
        result.fail("plug-in has nothing Capri can use", "it needs a .mcp.json with a server she starts, or skills in skills/<name>/SKILL.md")
    return used


def plugin_skills(manifest, files, root, lower):
    places = []
    listed = manifest.get('skills') if isinstance(manifest, dict) else None
    if isinstance(listed, str):
        places.append(listed)
    elif isinstance(listed, list):
        places += [one for one in listed if isinstance(one, str)]
    if not any(one in ('skills', './skills', './skills/') for one in places):
        places.append('skills')
    found = []
    top = posixpath.normpath('/plugin/' + root)
    first = lower.get((root + 'SKILL.md').lower())
    if first:
        found.append(first)
    for place in places:
        full = posixpath.normpath(posixpath.join(top, place.replace('\\', '/')))
        if full != top and not full.startswith(top + '/'):
            continue
        folder = full[len('/plugin/'):] + '/' if full != '/plugin' else ''
        inner = sorted({entry[len(folder):].split('/', 1)[0] for entry in files if entry.lower().startswith(folder.lower()) and '/' in entry[len(folder):]})
        for one in [''] + [one + '/' for one in inner]:
            skill = lower.get((folder + one + 'SKILL.md').lower())
            if skill and skill not in found:
                found.append(skill)
    return found


class DiskSource:
    def folders(self):
        return sorted(f for f in os.listdir(root) if os.path.isdir(os.path.join(root, f)))

    def exists(self, folder):
        return os.path.isdir(os.path.join(root, folder))

    def files(self, folder):
        path = os.path.join(root, folder)
        return sorted(f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f)) and not os.path.islink(os.path.join(path, f)))

    def links(self, folder):
        path = os.path.join(root, folder)
        return sorted(f for f in os.listdir(path) if os.path.islink(os.path.join(path, f)))

    def read(self, folder, file):
        with open(os.path.join(root, folder, file), 'rb') as f:
            return f.read()


class GitSource:
    def __init__(self, commit):
        self.commit = commit

    def git(self, *args):
        return subprocess.run(['git', '-C', here] + list(args), capture_output=True, check=True).stdout

    def exists(self, folder):
        return bool(self.git('ls-tree', self.commit, 'mods/' + folder).strip())

    def rows(self, folder):
        out = self.git('ls-tree', '-z', self.commit, 'mods/' + folder + '/').decode('utf-8', 'replace')
        for record in out.split('\0'):
            if record:
                meta, path = record.split('\t', 1)
                yield meta.split()[0], meta.split()[1], path.split('/', 2)[2]

    def files(self, folder):
        return sorted(name for mode, kind, name in self.rows(folder) if kind == 'blob' and mode != '120000')

    def links(self, folder):
        return sorted(name for mode, kind, name in self.rows(folder) if mode == '120000' or kind == 'commit')

    def read(self, folder, file):
        return self.git('cat-file', 'blob', self.commit + ':mods/' + folder + '/' + file)

    def changed(self, base):
        out = self.git('diff', '--name-only', '--no-renames', '-z', base, self.commit, '--', 'mods/').decode('utf-8', 'replace')
        folders = {p.split('/')[1] for p in out.split('\0') if p.count('/') >= 2}
        return sorted(f for f in folders if self.exists(f))


def check_folder(folder, source=None):
    source = source or DiskSource()
    result = Result(folder)
    for file in source.links(folder):
        result.fail("a link in the mod folder", "`" + file + "` is a link, not a file")
    for file in source.files(folder):
        if file == 'preview.png':
            if len(source.read(folder, file)) > 2 * mb:
                result.fail("preview picture too big", "`preview.png` is over 2 MB")
            continue
        if not file.endswith(kinds):
            continue
        data = source.read(folder, file)
        if file.endswith('.capri-code'):
            check_secrets(result, file, data)
            check_code(result, file, data)
        elif file.endswith('.capri-plugin'):
            check_plugin(result, file, data)
        elif file.endswith(('.capri-skin', '.capri-skill')) and zipfile.is_zipfile(io.BytesIO(data)):
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    for info in zf.infolist():
                        if not info.is_dir() and info.file_size <= 8 * mb:
                            check_secrets(result, file + ":" + info.filename, zf.read(info))
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError, OSError):
                check_secrets(result, file, data)
        else:
            check_secrets(result, file, data)
            check_settings_folder(result, text_of(data))
    return result


def plain(text):
    text = ''.join(c if ' ' <= c <= '~' else '?' for c in str(text))
    return text.replace('::', ': :').replace('##[', '# #[')


def report(results):
    failing = [r for r in results if r.fails]
    warned = [r for r in results if r.warns and not r.fails]
    lines = ["## Mod checks", "", "Mod checks: " + str(len(failing)) + " to fix", "",
             "Checked " + str(len(results)) + " mod folder" + ("" if len(results) == 1 else "s") + ": "
             + str(len(failing)) + " with hard failures, " + str(sum(1 for r in results if r.warns)) + " with warnings.", ""]
    for r in results:
        if not r.fails and not r.warns:
            continue
        lines.append("### `" + plain(r.folder) + "`")
        for rule, why in r.fails:
            lines.append("- **FAIL** " + plain(rule) + ": " + plain(why))
        for text in r.warns:
            lines.append("- warning: " + plain(text))
        lines.append("")
    if not failing and not warned:
        lines.append("Nothing to flag.")
    return "\n".join(lines).rstrip() + "\n"


def main(argv):
    args = argv[1:]
    source = DiskSource()
    if args and args[0] == '--changed':
        if len(args) != 2:
            raise SystemExit("usage: check-mods.py [--all | --changed BASE_SHA | folder ...] | PARENT COMMIT")
        source = GitSource('HEAD')
        folders = source.changed(args[1])
    elif len(args) == 2 and not os.path.isdir(os.path.join(root, args[0])):
        source = GitSource(args[1])
        folders = source.changed(args[0])
    elif args == ['--all'] or not args:
        folders = source.folders()
    else:
        folders = [os.path.basename(a.rstrip('/\\')) for a in args]
        missing = [f for f in folders if not source.exists(f)]
        if missing:
            raise SystemExit("no such mod folder: " + ", ".join(missing))
    results = [check_folder(f, source) for f in folders]
    text = report(results)
    sys.stdout.write(text)
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as f:
            f.write(text)
    return 1 if any(r.fails for r in results) else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
