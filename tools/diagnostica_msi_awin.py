#!/usr/bin/env python3
"""Read MSI feed metadata with the existing Awin feed key; never change settings."""
from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import os
import re
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

MSI_ADVERTISER_ID = '130769'
MAX_RESPONSE = 8 * 1024 * 1024
FIELDS = {
    'advertiserid', 'advertisername', 'merchantid', 'merchantname',
    'membershipstatus', 'datafeedformat', 'feedid', 'datafeedid',
    'feedname', 'datafeedname', 'primaryregion', 'language',
    'noofproducts', 'numberofproducts', 'productcount', 'products',
    'lastimported', 'lastupdated',
}


def normalized(value):
    return re.sub(r'[^a-z0-9]', '', str(value).lower())


def configuration(root):
    env_file = root / '.env'
    text = env_file.read_text(encoding='utf-8-sig') if env_file.is_file() else ''
    values = {}
    for line in text.splitlines():
        match = re.match(r'^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$', line)
        if match:
            values[match[1]] = match[2].strip().strip('"\'')
    values.update({key: value for key, value in os.environ.items() if key.startswith('AWIN_')})
    return values, text


def feed_key(root):
    values, text = configuration(root)
    candidates = [values.get(name, '') for name in ('AWIN_FEED_URL', 'AWIN_FEED_URLS')]
    candidates.append(text)
    for candidate in candidates:
        for _ in range(4):
            expanded = re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}',
                              lambda m: values.get(m[1], ''), candidate)
            if expanded == candidate:
                break
            candidate = expanded
        match = re.search(r'https://productdata\.awin\.com/[^\s"\']*?/apikey/([A-Za-z0-9_-]+)', candidate)
        if match:
            return match[1]
    for name in ('AWIN_DATAFEED_API_KEY', 'AWIN_DATAFEED_KEY', 'AWIN_FEED_API_KEY'):
        key = values.get(name, '')
        if re.fullmatch(r'[A-Za-z0-9_-]+', key):
            return key
    raise ValueError('Chiave feed non trovata nella configurazione esistente. Nessun file modificato.')


def publisher_id(root):
    values, text = configuration(root)
    for name in ('AWIN_PUBLISHER_ID', 'AWIN_AFFILIATE_ID', 'AWIN_AID'):
        value = values.get(name, '').strip()
        if value.isdigit():
            return value
    match = re.search(r'/aid/(\d+)(?:/|[;"\s]|$)', text)
    return match[1] if match else None


def feed_list_endpoint(root, key):
    publisher = publisher_id(root)
    if publisher:
        return ('elenco Awin attuale',
                'https://ui.awin.com/productdata-darwin-download/publisher/'
                + publisher + '/' + quote(key, safe='') + '/1/feedList')
    return ('elenco Awin precedente; Publisher ID non individuato',
            'https://productdata.awin.com/datafeed/list/apikey/' + quote(key, safe=''))


def cached_feed_lists(root):
    directories = [root, root.parent]
    for base in (root, root.parent):
        directories.extend(base / name for name in ('cache', '.cache', 'data', 'feeds', 'Downloads'))
    seen = set()
    for directory in directories:
        if not directory.is_dir():
            continue
        for path in directory.iterdir():
            if path in seen or path.is_symlink() or not path.is_file():
                continue
            seen.add(path)
            if not re.search(r'feed[ _-]?list|list[ _-]?feed|(?:lista|elenco).*(?:awin|feed)|awin.*list', path.name, re.I):
                continue
            if path.suffix.lower() not in {'.csv', '.json', '.gz', '.txt'}:
                continue
            try:
                if not 0 < path.stat().st_size <= MAX_RESPONSE:
                    continue
                yield path, parse_rows(path.read_bytes())
            except (OSError, ValueError, UnicodeError, csv.Error):
                continue


def parse_rows(raw):
    if raw.startswith(b'\x1f\x8b'):
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
            raw = stream.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise ValueError('Elenco feed troppo grande per questo controllo.')
    text = raw.decode('utf-8-sig')
    if text.lstrip().startswith('<'):
        raise ValueError('Awin ha restituito una pagina web invece dell\'elenco dei feed.')
    if text.lstrip().startswith(('[', '{')):
        data = json.loads(text)
        if isinstance(data, dict):
            if 'feeds' not in data and 'data' not in data:
                raise ValueError('La risposta JSON non contiene un elenco feed.')
            data = data.get('feeds', data.get('data'))
        if not isinstance(data, list) or not all(isinstance(row, dict) for row in data):
            raise ValueError('Formato elenco feed non riconosciuto.')
        return data
    try:
        delimiter = csv.Sniffer().sniff(text[:10000], delimiters=',;\t|').delimiter
    except csv.Error:
        delimiter = ','
    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    if not reader.fieldnames or not any(normalized(name) in FIELDS for name in reader.fieldnames):
        raise ValueError('Intestazione elenco feed non riconosciuta.')
    return list(reader)


def msi_rows(rows, secret):
    found = []
    for row in rows:
        normalized_row = {normalized(key): str(value or '').strip() for key, value in row.items()}
        advertiser_id = normalized_row.get('advertiserid', normalized_row.get('merchantid', ''))
        advertiser_name = normalized_row.get('advertisername', normalized_row.get('merchantname', ''))
        if advertiser_id:
            matches = advertiser_id == MSI_ADVERTISER_ID
        else:
            matches = bool(re.search(r'\bMSI\b', advertiser_name, re.I))
        if not matches:
            continue
        safe = {}
        for key, value in row.items():
            if normalized(key) not in FIELDS:
                continue
            value = str(value or '').strip()
            if secret:
                value = value.replace(secret, '[CHIAVE OMESSA]')
            if re.search(r'https?://|/apikey/', value, re.I):
                value = '[LINK OMESSO]'
            safe[str(key)] = value
        found.append(safe)
    return found


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dir', default='/home/simone/prezziassurdi_bot_raspberry')
    parser.add_argument('--offline', action='store_true', help='Controlla soltanto eventuali elenchi locali.')
    args = parser.parse_args(argv)
    root = Path(args.dir).expanduser().resolve()
    print('Controllo MSI IT v2 - programma ' + MSI_ADVERTISER_ID)
    try:
        key = feed_key(root)
        local_count = 0
        for path, cached_rows in cached_feed_lists(root):
            local_count += 1
            found = msi_rows(cached_rows, key)
            if found:
                print('Feed MSI trovati in un elenco locale; disponibilita attuale da confermare.')
                print('File: ' + path.name.replace(key, '[CHIAVE OMESSA]'))
                for row in found:
                    print(json.dumps(row, ensure_ascii=True))
                print('Nessun file modificato. Chiavi e link di download omessi.')
                return 0
        print('Elenchi locali esaminati: ' + str(local_count) + '; nessun feed MSI individuato in queste copie.')
        if args.offline:
            print('Verifica online non eseguita. Nessun file modificato.')
            return 0
        label, endpoint = feed_list_endpoint(root, key)
        print('Contatto: ' + label)
        request = Request(endpoint,
                          headers={'User-Agent': 'PrezziAssurdi-FeedCheck/2.0',
                                   'Accept': 'text/csv,application/json;q=0.9,*/*;q=0.5'})
        with urlopen(request, timeout=30) as response:
            raw = response.read(MAX_RESPONSE + 1)
        rows = parse_rows(raw)
        found = msi_rows(rows, key)
    except HTTPError as error:
        print('Awin risponde con errore HTTP ' + str(error.code) + '. Catalogo MSI non verificato.')
        print('Nessun file modificato. In caso di HTTP 503 attendere almeno 5 minuti prima di riprovare.')
        return 2
    except (URLError, TimeoutError, OSError):
        print('Connessione Awin non riuscita. Nessun file modificato.')
        return 2
    except (ValueError, UnicodeError, csv.Error):
        print('Configurazione o risposta Awin non leggibile. Nessun file modificato.')
        return 2
    print('Feed esaminati: ' + str(len(rows)))
    if found:
        print('Feed MSI trovati: ' + str(len(found)))
        for row in found:
            print(json.dumps(row, ensure_ascii=True))
    else:
        print('MSI IT non compare nell\'elenco dei feed restituito da Awin.')
    print('Controllo completato. Nessun file modificato. Chiavi e link di download omessi.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
