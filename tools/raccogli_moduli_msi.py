#!/usr/bin/env python3
"""Create redacted analysis copies of search modules; do not change the application."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import sys
import zipfile
from pathlib import Path

REDACTED = '[REDACTED]'
PATTERNS = ('*awin*.py', '*identity*.py', '*store*.py', '*search*.py')
EXPLICIT = ('pa_merchant_policy.py', 'pa_site_layout.py', 'site_style.py')
MAX_SIZE = 2 * 1024 * 1024


def sensitive_name(name):
    return bool(re.search(r'(?:^|_)(?:token|password|passwd|secret|api_key|apikey|access_key|'
                          r'access_token|refresh_token|client_secret|authorization|credential)(?:$|_)',
                          str(name), re.I))


class AllStrings(ast.NodeTransformer):
    def visit_Constant(self, node):
        if isinstance(node.value, str):
            return ast.copy_location(ast.Constant(REDACTED), node)
        if isinstance(node.value, bytes):
            return ast.copy_location(ast.Constant(REDACTED.encode()), node)
        return node


def scrub_text(value):
    if re.fullmatch(r'[a-fA-F0-9]{32,}', value):
        return REDACTED
    if re.fullmatch(r'[A-Za-z0-9_-]{28,256}', value) and re.search(r'[0-9]', value):
        return REDACTED
    value = re.sub(r'(/apikey/)[^/\s"\'<>]+', r'\1' + REDACTED, value, flags=re.I)
    value = re.sub(r'(/productdata-darwin-download/publisher/\d+/)[^/\s"\'<>]+',
                   r'\1' + REDACTED, value, flags=re.I)
    value = re.sub(r'([?&](?:api[_-]?key|token|access_token|secret|password)=)[^&\s"\'<>]+',
                   r'\1' + REDACTED, value, flags=re.I)
    value = re.sub(r'\bBearer\s+[A-Za-z0-9._~+/-]+', 'Bearer ' + REDACTED, value, flags=re.I)
    value = re.sub(r'\b\d{6,12}:[A-Za-z0-9_-]{25,}\b', REDACTED, value)
    value = re.sub(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b', REDACTED, value)
    return value


class Redactor(ast.NodeTransformer):
    def visit_Constant(self, node):
        if isinstance(node.value, str):
            return ast.copy_location(ast.Constant(scrub_text(node.value)), node)
        return node

    def visit_Assign(self, node):
        names = [part.id for target in node.targets for part in ast.walk(target)
                 if isinstance(part, ast.Name)]
        if any(sensitive_name(name) for name in names):
            node.value = AllStrings().visit(node.value)
        return self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if isinstance(node.target, ast.Name) and sensitive_name(node.target.id) and node.value:
            node.value = AllStrings().visit(node.value)
        return self.generic_visit(node)

    def visit_Dict(self, node):
        for index, key in enumerate(node.keys):
            if isinstance(key, ast.Constant) and isinstance(key.value, str) and sensitive_name(key.value):
                node.values[index] = AllStrings().visit(node.values[index])
        return self.generic_visit(node)

    def visit_keyword(self, node):
        if node.arg and sensitive_name(node.arg):
            node.value = AllStrings().visit(node.value)
        return self.generic_visit(node)

    def visit_arguments(self, node):
        args = node.posonlyargs + node.args
        for index, (arg, value) in enumerate(zip(args[len(args) - len(node.defaults):], node.defaults)):
            if sensitive_name(arg.arg):
                node.defaults[index] = AllStrings().visit(value)
        for index, (arg, value) in enumerate(zip(node.kwonlyargs, node.kw_defaults)):
            if value is not None and sensitive_name(arg.arg):
                node.kw_defaults[index] = AllStrings().visit(value)
        return self.generic_visit(node)


def analysis_copy(source):
    tree = ast.parse(source)
    tree = Redactor().visit(tree)
    ast.fix_missing_locations(tree)
    result = '# COPIA REDATTA PER ANALISI: NON INSTALLARE COME MODULO.\n' + ast.unparse(tree) + '\n'
    compile(result, '<analysis-copy>', 'exec')
    return result


def collect(root, output):
    paths = {path for pattern in PATTERNS for path in root.glob(pattern)}
    paths.update(root / name for name in EXPLICIT if (root / name).is_file())
    selected = []
    for path in sorted(paths):
        if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_SIZE:
            continue
        selected.append(path)
    if not selected:
        raise ValueError('Nessun modulo del motore trovato nella cartella indicata.')
    entries = {}
    manifest = {'purpose': 'MSI search integration - redacted analysis copies', 'files': []}
    for path in selected:
        raw = path.read_bytes()
        source = raw.decode('utf-8-sig')
        entries['moduli/' + path.name] = analysis_copy(source).encode('utf-8')
        manifest['files'].append({'name': path.name, 'original_sha256': hashlib.sha256(raw).hexdigest(),
                                  'original_size': len(raw)})
    env_file = root / '.env'
    if env_file.is_file():
        text = env_file.read_text(encoding='utf-8-sig')
        manifest['awin_setting_names'] = sorted(set(re.findall(r'^\s*(AWIN_[A-Z0-9_]+)\s*=', text, re.M)))
    entries['manifest.json'] = json.dumps(manifest, ensure_ascii=True, indent=2).encode('utf-8')
    entries['LEGGIMI.txt'] = (
        'Copie redatte dei moduli per preparare l\'integrazione MSI.\n'
        'Non installare queste copie come moduli: sono solo materiale per analisi.\n'
        'Il file .env non e\' incluso; nel manifest sono riportati soltanto i nomi delle impostazioni Awin.\n'
        'Il programma non modifica i sorgenti installati e non riavvia servizi.\n'
    ).encode('utf-8')
    temporary = output.with_name(output.name + '.pending')
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
                for name, content in entries.items():
                    archive.writestr(name, content)
        os.replace(temporary, output)
    finally:
        if temporary.exists():
            temporary.unlink()
    return len(selected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dir', default='/home/simone/prezziassurdi_bot_raspberry')
    parser.add_argument('--output', default='/home/simone/PrezziAssurdi_Moduli_MSI.zip')
    args = parser.parse_args()
    try:
        count = collect(Path(args.dir).expanduser().resolve(), Path(args.output).expanduser().resolve())
    except Exception:
        print('Raccolta non completata. I moduli installati non sono stati modificati.', file=sys.stderr)
        return 2
    print('Archivio pronto: ' + str(Path(args.output).expanduser().resolve()))
    print('Moduli copiati per analisi: ' + str(count) + '. File .env escluso.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
