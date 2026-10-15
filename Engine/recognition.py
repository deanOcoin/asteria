"""Atlas signatures: relocation-aware fingerprints of whole function bodies, not an IDA .sig reader.
A match keeps internal branch geometry and named external refs; one fingerprint under distinct names picks none."""
import collections
import hashlib
import json
import os
from pathlib import Path
import re

SCHEMA = 'asteria.atlas/1'
MAX_PACK = 8 * 1024 * 1024
MAX_ENTRIES = 20000
MAX_OPS = 3000
PADDING = frozenset(('nop', 'nopl', 'nopw', 'int3', 'udf'))


def anonymous(name):
    return not name or bool(re.match(r'^(sub_|ltmp|Ltmp|\.L|LBB|lBB|entry$|\.text$|__text$|stubs)', name))


def canonical(name):
    return name.lstrip('_').split('@')[0]


def signature_directory():
    return Path(os.environ.get('ASTERIA_SIGNATURE_DIR', str(Path.home() / 'Library/Application Support/Asteria/Signatures')))


def target_names(a):
    names = {}
    for f in a.get('symbols', []) + a.get('functions', []):
        if not anonymous(f['name']) and f['address'] not in ('', '0x0'):
            names.setdefault(f['address'], canonical(f['name']))
    return names


def fingerprint(items, names):
    """Only direct control-flow targets are abstracted; data addresses and relocations stay literal,
    which costs coverage but rules out weak, address-only matches."""
    indexes = {i['address']: n for n, i in enumerate(items)}
    if len(indexes) != len(items):
        return None
    result = []
    for i in items:
        raw = i.get('bytes', '')
        if not raw or i['offset'] < 0:
            return None
        operands = i['operands'].split('<')[0].split(' //')[0].split(' # ')[0].strip()
        target = i.get('target', '')
        if target and i['kind'] in ('branch', 'jump', 'call'):
            if target in indexes:
                target_key = 'local:%d' % indexes[target]
            elif target in names:
                target_key = 'ref:' + names[target]
            else:
                return None
            operands, replaced = re.subn(r'(?<![\w])#?0x[0-9a-fA-F]+(?![\w])', target_key, operands, count=1)
            if not replaced:
                return None
            # Width and mnemonic retain encoding constraints after relocation.
            result.append('%s/%d %s' % (i['mnemonic'], len(raw.split()), operands))
        else:
            result.append('%s %s | %s' % (i['mnemonic'], operands, raw.lower()))
    return result


def trim_padding(items):
    items = list(items)
    while items and items[-1]['mnemonic'] in PADDING:
        items.pop()
    return items


def validate(pack):
    if not isinstance(pack, dict) or pack.get('schema') != SCHEMA:
        raise ValueError('Expected an Asteria Atlas signature pack (asteria.atlas/1), not an IDA .sig file')
    if not isinstance(pack.get('library'), str) or not 1 <= len(pack['library']) <= 160:
        raise ValueError('Signature library name must contain 1–160 characters')
    entries = pack.get('entries')
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise ValueError('Invalid signature entry count')
    for e in entries:
        if not isinstance(e, dict) or not isinstance(e.get('name'), str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,159}', e['name']):
            raise ValueError('Signature names must be identifiers of at most 160 characters')
        if e.get('arch') not in ('arm64', 'arm64e', 'aarch64', 'x86', 'x86_64') or e.get('bits') not in (32, 64) or e.get('endian') != 'little':
            raise ValueError('Unsupported signature architecture')
        ops = e.get('ops')
        if not isinstance(ops, list) or not 4 <= len(ops) <= MAX_OPS or any(not isinstance(o, str) or len(o) > 2048 for o in ops):
            raise ValueError('Signatures need 4–3,000 bounded instruction records')
        if not isinstance(e.get('size'), int) or not 16 <= e['size'] <= 48000:
            raise ValueError('Signatures need at least 16 bytes')
    return pack


def read_pack(path):
    path = Path(path).expanduser()
    if path.stat().st_size > MAX_PACK:
        raise ValueError('Signature pack exceeds 8 MiB')
    return validate(json.loads(path.read_text()))


def load_packs():
    packs, errors = [], []
    paths = sorted((Path(__file__).parent / 'signatures').glob('*.atlas.json')) + sorted(signature_directory().glob('*.atlas.json'))
    total = 0
    for path in paths[:128]:
        try:
            pack = read_pack(path)
            total += len(pack['entries'])
            if total > MAX_ENTRIES:
                raise ValueError('Combined signature limit exceeded (20,000 entries)')
            packs.append((pack, str(path)))
        except (ValueError, OSError, KeyError, TypeError) as error:
            errors.append('%s: %s' % (path.name, error))
    return packs, errors


def learn(a, library, selected=None):
    entries, skipped = [], []
    names = target_names(a)
    counts = collections.Counter(i['address'] for i in a['instructions'])
    by_function = collections.defaultdict(list)
    for ins in a['instructions']: by_function[ins['function']].append(ins)
    for f in a['functions']:
        if selected and f['address'] not in selected:
            continue
        if anonymous(f['name']) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,159}', f['name']):
            skipped.append(f['name'] + ': no usable name'); continue
        items = trim_padding([i for i in by_function[f['name']] if int(f['address'], 16) <= int(i['address'], 16) <= int(f['end'], 16)])
        size = sum(len(i['bytes'].split()) for i in items)
        if not 4 <= len(items) <= MAX_OPS or size < 16 or any(counts[i['address']] > 1 for i in items):
            skipped.append(f['name'] + ': short or overlapping body'); continue
        ops = fingerprint(items, names)
        if ops is None:
            skipped.append(f['name'] + ': unresolved reference or missing bytes'); continue
        entries.append(dict(name=f['name'], arch=a['arch'], bits=a['bits'], endian=a['endian'], size=size, ops=ops))
    pack = validate(dict(schema=SCHEMA, library=library, entries=entries, sourceHash=a['sha256']))
    return dict(pack=pack, count=len(entries), skipped=skipped)


def install(path):
    pack = read_pack(path)
    if not pack['entries']:
        raise ValueError('This signature pack contains no entries')
    data = json.dumps(pack, sort_keys=True, indent=2).encode()
    directory = signature_directory(); directory.mkdir(parents=True, exist_ok=True)
    destination = directory / (hashlib.sha256(data).hexdigest()[:24] + '.atlas.json')
    # Content-addressed names make importing the same pack idempotent.
    temporary = destination.with_suffix('.tmp'); temporary.write_bytes(data); temporary.replace(destination)
    return dict(path=str(destination), library=pack['library'], count=len(pack['entries']))


def recognize(a, packs=None):
    if packs is None:
        packs, errors = load_packs()
    else:
        packs, errors = [(validate(p), 'provided') for p in packs], []
    summary = dict(engine='Atlas 1', signatures=sum(len(p['entries']) for p, _ in packs), libraries=[p['library'] for p, _ in packs], matches=[], ambiguities=[], warnings=errors)
    a['recognition'] = summary
    for f in a['functions']:
        f.setdefault('originalName', f['name'])
        f.setdefault('nameSource', 'heuristic' if anonymous(f['name']) else 'symbol')
    if len({i['address'] for i in a['instructions']}) != len(a['instructions']):
        summary['warnings'].append('Signature matching skipped: overlapping section-relative code addresses. Use a linked image with unique virtual addresses.')
        return summary
    index = collections.defaultdict(list)
    for pack, path in packs:
        for e in pack['entries']:
            if (e['arch'], e['bits'], e['endian']) == (a['arch'], a['bits'], a['endian']):
                # A coarse first-op index avoids trying every pack entry per VA.
                index[e['ops'][0].split(' ')[0]].append((e, pack['library']))
    names = target_names(a)
    sections = collections.defaultdict(list)
    for ins in a['instructions']:
        sections[ins['section']].append(ins)
    starts = {f['address'] for f in a['functions']}
    starts.update(i['target'] for i in a['instructions'] if i['kind'] == 'call')
    found = []
    owners_by_name = {f['name']: f for f in a['functions']}
    functions_by_address = {f['address']: f for f in a['functions']}
    named_addresses = collections.defaultdict(set)
    for f in a['functions']: named_addresses[f['name']].add(f['address'])
    for section, items in sections.items():
        previous_code = None
        for n, ins in enumerate(items):
            # candidates are known entries or the first instruction after a return/padding run;
            # tracking the previous non-padding instruction forward avoids a quadratic walk back over INT3 runs
            after_return = previous_code is not None and previous_code['kind'] == 'return'
            if ins['mnemonic'] not in PADDING: previous_code = ins
            if ins['address'] not in starts and not after_return:
                continue
            owner = owners_by_name.get(ins['function'])
            if owner and not anonymous(owner['name']) and owner['address'] != ins['address']:
                continue
            candidates = []
            keys = (ins['mnemonic'], ins['mnemonic'] + '/' + str(len(ins['bytes'].split())))
            for key in keys:
                for e, library in index.get(key, []):
                    window = items[n:n + len(e['ops'])]
                    if len(window) != len(e['ops']) or sum(len(i['bytes'].split()) for i in window) != e['size']:
                        continue
                    if any(int(right['address'], 16) != int(left['address'], 16) + len(left['bytes'].split()) for left, right in zip(window, window[1:])):
                        continue
                    # Do not consume another discovered function start.
                    if any(i['address'] in starts for i in window[1:]):
                        continue
                    if fingerprint(window, names) == e['ops']:
                        candidates.append((e, library, window))
            if not candidates:
                continue
            distinct = {canonical(e['name']) for e, _, _ in candidates}
            if len(distinct) != 1:
                summary['ambiguities'].append(dict(address=ins['address'], names=sorted(distinct)))
                continue
            e, library, window = max(candidates, key=lambda c: len(c[0]['ops']))
            existing = functions_by_address.get(ins['address'])
            applied = existing is None or anonymous(existing['name'])
            display = e['name']
            # Keep names unique so a function's stable address remains unambiguous.
            if named_addresses[display] - {ins['address']}:
                display += '_' + ins['address'][2:]
            record = dict(address=ins['address'], name=display, library=library, instructions=len(window), size=e['size'], applied=applied)
            summary['matches'].append(record)
            if applied:
                found.append((section, n + len(window) - 1, window, existing, record))
    # Repartition once from explicit boundaries, preserving original evidence.
    # This also handles several matches recovered from one stripped code region.
    boundaries = {}
    if found:
        instructions_by_owner = {(i['address'], i['function']): i for i in a['instructions']}
        for f in a['functions']:
            ins = instructions_by_owner.get((f['address'], f['name']))
            if ins: boundaries[(ins['section'], f['address'])] = dict(f)
    for section, last_index, window, existing, record in found:
        first = window[0]['address']
        boundaries[(section, first)] = dict(name=record['name'], originalName=existing.get('originalName', existing['name']) if existing else 'sub_' + first[2:], nameSource='signature', library=record['library'], address=first, end=window[-1]['address'], count=len(window))
        section_items = sections[section]
        following = last_index + 1
        while following < len(section_items) and section_items[following]['mnemonic'] in PADDING:
            following += 1
        if following < len(section_items):
            address = section_items[following]['address']
            boundaries.setdefault((section, address), dict(name='sub_' + address[2:], originalName='sub_' + address[2:], nameSource='heuristic', address=address, end=address, count=0))
    if found:
        rebuilt = []
        for section, items in sections.items():
            current = None
            for ins in items:
                if (section, ins['address']) in boundaries:
                    current = boundaries[(section, ins['address'])]
                    current['count'] = 0
                    rebuilt.append(current)
                if current:
                    ins['function'] = current['name']
                    current['count'] += 1
                    current['end'] = ins['address']
        a['functions'] = rebuilt
    a['functions'].sort(key=lambda f: int(f['address'], 16))
    owners = {i['address']: i['function'] for i in a['instructions']}
    for ref in a['xrefs']:
        ref['function'] = owners.get(ref['source'], ref['function'])
    return summary


def apply_names(a, names):
    """Address-scoped analyst names, separate from original symbol evidence."""
    if not names:
        return
    if not isinstance(names, dict) or len(names) > 20000:
        raise ValueError('Invalid function name map')
    from decompiler import ident
    for address, name in names.items():
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,79}', name) or ident(name) != name:
            raise ValueError('Function names must be nonreserved C identifiers (up to 80 characters)')
    final_names = [names.get(f['address'], f['name']) for f in a['functions']]
    if len(final_names) != len(set(final_names)):
        raise ValueError('Function name collides with another function')
    # Apply all overrides in one pass. Reading original owners before writing
    # names also handles swaps without cascading one rename into the next.
    replacements = collections.defaultdict(list)
    for f in a['functions']:
        if f['address'] not in names:
            continue
        old = f['name']; f.setdefault('originalName', old); f['semanticName'] = old; f['name'] = names[f['address']]; f['nameSource'] = 'analyst'
        replacements[old].append((int(f['address'], 16), int(f['end'], 16), f['name']))
    for ins in a['instructions']:
        for start, end, name in replacements.get(ins['function'], ()):
            if start <= int(ins['address'], 16) <= end:
                ins['function'] = name; break
    for ref in a['xrefs']:
        for start, end, name in replacements.get(ref['function'], ()):
            if start <= int(ref['source'], 16) <= end:
                ref['function'] = name; break
