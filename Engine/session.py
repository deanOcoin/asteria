"""In-memory analysis cache for the static worker; nothing is persisted to disk.
The binary is rehashed on every request, and keys include the slice and signature-pack identities."""
from collections import OrderedDict
import hashlib
from pathlib import Path
import analysis
import recognition


def signature_identity():
    roots = (Path(recognition.__file__).parent / 'signatures', recognition.signature_directory())
    values = []
    for root in roots:
        for path in sorted(root.glob('*.atlas.json'))[:128]:
            try:
                s = path.stat()
                values.append((str(path), s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns))
            except OSError:
                values.append((str(path), 'unavailable'))
    return tuple(values)


class AnalysisSession:
    def __init__(self, max_entries=3, max_instructions=180000):
        self.entries = OrderedDict()
        self.max_entries = max_entries
        self.max_instructions = max_instructions

    def analyze(self, path, slice_index=0, function_names=None, refresh=False):
        resolved, data = analysis.load_file(path)
        digest = hashlib.sha256(data).hexdigest()
        key = (str(resolved), slice_index, digest, signature_identity())
        cached = None if refresh else self.entries.get(key)
        if cached is None:
            cached = analysis.analyze(resolved, slice_index)
            if cached['sha256'] != digest:
                raise ValueError('Binary changed while it was being analyzed; reopen it')
            self.entries[key] = cached
        self.entries.move_to_end(key)
        while len(self.entries) > self.max_entries or (len(self.entries) > 1 and sum(len(a['instructions']) for a in self.entries.values()) > self.max_instructions):
            self.entries.popitem(last=False)
        if not function_names:
            return cached
        # Analyst names are an overlay. Only dictionaries that may be changed are
        # copied, leaving the cached base and other projects' names untouched.
        result = dict(cached)
        renamed = {f['name'] for f in cached['functions'] if f['address'] in function_names}
        result['functions'] = [dict(f) for f in cached['functions']]
        result['instructions'] = [dict(i) if i['function'] in renamed else i for i in cached['instructions']]
        result['xrefs'] = [dict(r) if r['function'] in renamed else r for r in cached['xrefs']]
        recognition.apply_names(result, function_names)
        return result

    def clear(self):
        self.entries.clear()
