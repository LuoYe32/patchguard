import dis
import types


def _qualname(code):
    return (getattr(code, 'co_qualname', None) or code.co_name).replace('.<locals>.', '.')


def code_objects(src, filename='<src>'):
    """Map qualname -> list of code objects found in the source."""
    out = {}
    stack = [compile(src, filename, 'exec')]
    while stack:
        code = stack.pop()
        out.setdefault(_qualname(code), []).append(code)
        stack.extend(c for c in code.co_consts if isinstance(c, types.CodeType))
    return out


def imported_modules(src):
    """(enclosing qualname, imported module) pairs from IMPORT_NAME instructions."""
    found = set()
    for qual, codes in code_objects(src).items():
        for code in codes:
            for ins in dis.get_instructions(code):
                if ins.opname == 'IMPORT_NAME':
                    found.add((qual, ins.argval))
    return found


def attribute_reads(src, qualname, param):
    """Names loaded as param.<name> inside functions called qualname, as a multiset."""
    reads = []
    for code in code_objects(src).get(qualname, []):
        prev = None
        for ins in dis.get_instructions(code):
            if ins.opname in ('LOAD_ATTR', 'LOAD_METHOD') and prev is not None \
                    and prev.opname in ('LOAD_FAST', 'LOAD_DEREF', 'LOAD_CLOSURE') and prev.argval == param:
                reads.append(ins.argval)
            prev = ins
    return sorted(reads)


def positional_params(src, qualname):
    """Positional and keyword-only parameter names of each function called qualname."""
    return [c.co_varnames[:c.co_argcount + c.co_kwonlyargcount] for c in code_objects(src).get(qualname, [])]


def verify_injection(info, before_src, after_src):
    """Return {'verified': bool, 'detail': str} for an injection described by info."""
    try:
        kind = info['type']
        if kind == 'E':
            new = imported_modules(after_src) - imported_modules(before_src)
            ok = any(mod == info['target_pkg'] and qual != '<module>' for qual, mod in new)
            return {'verified': ok, 'detail': f"new function-scoped imports: {sorted(m for _, m in new)}"}
        if kind == 'read-set':
            qual, param, attr = info['qualname'], info['param'], info['attr']
            before, after = attribute_reads(before_src, qual, param), attribute_reads(after_src, qual, param)
            return {'verified': after.count(attr) == before.count(attr) + 1,
                    'detail': f"{param}.{attr}: {before.count(attr)} -> {after.count(attr)} loads"}
        if kind == 'D-signature':
            qual, param = info['function'], info['param']
            before, after = positional_params(before_src, qual), positional_params(after_src, qual)
            ok = bool(before) and bool(after) and any(
                param in a and param not in b and len(a) == len(b) + 1 for b, a in zip(before, after))
            return {'verified': ok, 'detail': f"{qual}: {[list(p) for p in before]} -> {[list(p) for p in after]}"}
        return {'verified': False, 'detail': f"unknown injection type {kind!r}"}
    except (SyntaxError, KeyError, ValueError) as e:
        return {'verified': False, 'detail': f"{type(e).__name__}: {e}"}
