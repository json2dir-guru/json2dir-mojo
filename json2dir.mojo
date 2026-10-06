# json2dir: create the directory tree a JSON document describes, in the current directory.
# Implements RFC J2D-1 (https://github.com/kitsunoff/awesome-json2dir/blob/main/spec/rfc-json2dir.md).
# Mojo standard library only: hand-written UTF-8 check and JSON parser; libc via external_call.

from std.sys import argv, exit
from std.ffi import external_call, c_int, c_ssize_t
from std.io import FileDescriptor
from std.os import mkdir, unlink, symlink, lstat

comptime OBJECT = 0
comptime FILE = 1
comptime LINK = 2
comptime SCRIPT = 3
comptime MAX_DEPTH = 1000


@fieldwise_init
struct Node(Copyable, Movable):
    var kind: Int
    var data: List[UInt8]  # file content or link target
    var names: List[List[UInt8]]  # object member names
    var kids: List[Int]  # object member values (indices into the node arena)


def bytes_str(b: List[UInt8]) -> String:
    return String(unsafe_from_utf8=Span(b))


# §3: strict UTF-8 (no overlongs, no surrogates, nothing above U+10FFFF).
def check_utf8(s: List[UInt8]) raises:
    var i = 0
    var n = len(s)
    while i < n:
        var c = Int(s[i])
        if c < 0x80:
            i += 1
            continue
        var need: Int
        var lo = 0x80
        var hi = 0xBF
        if c >= 0xC2 and c <= 0xDF:
            need = 1
        elif c >= 0xE0 and c <= 0xEF:
            need = 2
            if c == 0xE0:
                lo = 0xA0
            elif c == 0xED:
                hi = 0x9F
        elif c >= 0xF0 and c <= 0xF4:
            need = 3
            if c == 0xF0:
                lo = 0x90
            elif c == 0xF4:
                hi = 0x8F
        else:
            raise Error("input is not valid UTF-8")
        if i + need >= n:
            raise Error("input is not valid UTF-8")
        for k in range(1, need + 1):
            var d = Int(s[i + k])
            if k == 1:
                if d < lo or d > hi:
                    raise Error("input is not valid UTF-8")
            elif d < 0x80 or d > 0xBF:
                raise Error("input is not valid UTF-8")
        i += need + 1


def put_utf8(mut out: List[UInt8], cp: Int):
    if cp < 0x80:
        out.append(UInt8(cp))
    elif cp < 0x800:
        out.append(UInt8(0xC0 | (cp >> 6)))
        out.append(UInt8(0x80 | (cp & 0x3F)))
    elif cp < 0x10000:
        out.append(UInt8(0xE0 | (cp >> 12)))
        out.append(UInt8(0x80 | ((cp >> 6) & 0x3F)))
        out.append(UInt8(0x80 | (cp & 0x3F)))
    else:
        out.append(UInt8(0xF0 | (cp >> 18)))
        out.append(UInt8(0x80 | ((cp >> 12) & 0x3F)))
        out.append(UInt8(0x80 | ((cp >> 6) & 0x3F)))
        out.append(UInt8(0x80 | (cp & 0x3F)))


def same(a: List[UInt8], b: List[UInt8]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def less(a: List[UInt8], b: List[UInt8]) -> Bool:
    var n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return a[i] < b[i]
    return len(a) < len(b)


def is_lit(a: List[UInt8], lit: StringSlice) -> Bool:
    var b = lit.as_bytes()
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


# §4.2.1: simple names only.
def check_name(name: List[UInt8]) raises:
    if len(name) == 0 or is_lit(name, ".") or is_lit(name, ".."):
        raise Error("invalid name " + bytes_str(name))
    for i in range(len(name)):
        if name[i] == UInt8(0x2F) or name[i] == UInt8(0):
            raise Error("invalid name " + bytes_str(name))


struct Parser:
    var src: List[UInt8]
    var pos: Int
    var nodes: List[Node]

    def __init__(out self, var src: List[UInt8]):
        self.src = src^
        self.pos = 0
        self.nodes = List[Node]()

    def fail(self, msg: String) raises:
        raise Error("input is not valid JSON: " + msg + " at byte " + String(self.pos))

    def ws(mut self):
        while self.pos < len(self.src):
            var c = self.src[self.pos]
            if c == UInt8(0x20) or c == UInt8(0x09) or c == UInt8(0x0A) or c == UInt8(0x0D):
                self.pos += 1
            else:
                break

    def peek(self) -> Int:
        if self.pos < len(self.src):
            return Int(self.src[self.pos])
        return -1

    def expect(mut self, c: Int) raises:
        self.ws()
        if self.peek() != c:
            self.fail("expected '" + chr(c) + "'")
        self.pos += 1

    def hex4(mut self) raises -> Int:
        var v = 0
        for _ in range(4):
            var c = self.peek()
            var d: Int
            if c >= 0x30 and c <= 0x39:
                d = c - 0x30
            elif c >= 0x61 and c <= 0x66:
                d = c - 0x61 + 10
            elif c >= 0x41 and c <= 0x46:
                d = c - 0x41 + 10
            else:
                self.fail("bad \\u escape")
                d = 0
            v = v * 16 + d
            self.pos += 1
        return v

    def string(mut self) raises -> List[UInt8]:
        self.ws()
        if self.peek() != 0x22:
            self.fail("expected string")
        self.pos += 1
        var out = List[UInt8]()
        while True:
            var c = self.peek()
            if c < 0:
                self.fail("unterminated string")
            self.pos += 1
            if c == 0x22:
                return out^
            if c < 0x20:
                self.fail("control character in string")
            if c != 0x5C:
                out.append(UInt8(c))
                continue
            var e = self.peek()
            self.pos += 1
            if e == 0x22 or e == 0x5C or e == 0x2F:
                out.append(UInt8(e))
            elif e == 0x62:
                out.append(8)
            elif e == 0x66:
                out.append(12)
            elif e == 0x6E:
                out.append(10)
            elif e == 0x72:
                out.append(13)
            elif e == 0x74:
                out.append(9)
            elif e == 0x75:
                var cp = self.hex4()
                if cp >= 0xD800 and cp <= 0xDBFF:
                    # §3.5: a high surrogate must be followed by an escaped low surrogate.
                    if self.peek() != 0x5C:
                        raise Error("string contains an unpaired surrogate")
                    self.pos += 1
                    if self.peek() != 0x75:
                        raise Error("string contains an unpaired surrogate")
                    self.pos += 1
                    var lo = self.hex4()
                    if lo < 0xDC00 or lo > 0xDFFF:
                        raise Error("string contains an unpaired surrogate")
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                elif cp >= 0xDC00 and cp <= 0xDFFF:
                    raise Error("string contains an unpaired surrogate")
                put_utf8(out, cp)
            else:
                self.fail("bad escape")

    # Parses a value and returns its node index. Only objects, strings and
    # ["link"|"script", string] arrays are accepted (§4); anything else is rejected.
    def value(mut self, depth: Int) raises -> Int:
        self.ws()
        var c = self.peek()
        if c == 0x22:
            var s = self.string()
            self.nodes.append(Node(FILE, s^, List[List[UInt8]](), List[Int]()))
            return len(self.nodes) - 1
        if c == 0x7B:
            return self.object(depth + 1)
        if c == 0x5B:
            self.pos += 1
            self.ws()
            if self.peek() != 0x22:
                raise Error('an array must be ["link", target] or ["script", content]')
            var kind = self.string()
            self.ws()
            if self.peek() != 0x2C:
                raise Error('an array must be ["link", target] or ["script", content]')
            self.pos += 1
            self.ws()
            if self.peek() != 0x22:
                raise Error('an array must be ["link", target] or ["script", content]')
            var payload = self.string()
            self.ws()
            if self.peek() != 0x5D:
                raise Error('an array must be ["link", target] or ["script", content]')
            self.pos += 1
            var k: Int
            if is_lit(kind, "link"):
                k = LINK
                for i in range(len(payload)):
                    if payload[i] == UInt8(0):
                        raise Error("a link target cannot contain NUL")
            elif is_lit(kind, "script"):
                k = SCRIPT
            else:
                raise Error("unknown array kind " + bytes_str(kind))
            self.nodes.append(Node(k, payload^, List[List[UInt8]](), List[Int]()))
            return len(self.nodes) - 1
        if c < 0:
            self.fail("unexpected end of input")
        raise Error("numbers, booleans and null are not allowed (or invalid JSON) at byte " + String(self.pos))

    def object(mut self, depth: Int) raises -> Int:
        if depth > MAX_DEPTH:
            raise Error("document is nested too deeply")
        self.expect(0x7B)
        var names = List[List[UInt8]]()
        var kids = List[Int]()
        self.ws()
        if self.peek() == 0x7D:
            self.pos += 1
        else:
            while True:
                var name = self.string()
                check_name(name)
                self.expect(0x3A)
                var v = self.value(depth)
                # Duplicate names: the last occurrence wins.
                var found = False
                for i in range(len(names)):
                    if same(names[i], name):
                        kids[i] = v
                        found = True
                if not found:
                    names.append(name^)
                    kids.append(v)
                self.ws()
                var c = self.peek()
                if c == 0x2C:
                    self.pos += 1
                    continue
                if c == 0x7D:
                    self.pos += 1
                    break
                self.fail("expected ',' or '}'")
        self.nodes.append(Node(OBJECT, List[UInt8](), names^, kids^))
        return len(self.nodes) - 1


def read_stdin() raises -> List[UInt8]:
    var out = List[UInt8]()
    var buf = List[UInt8](length=65536, fill=0)
    var fd = FileDescriptor(0)
    while True:
        var n = fd.read_bytes(Span(buf))
        if n <= 0:
            break
        for i in range(n):
            out.append(buf[i])
    return out^


# Returns -1 if nothing exists at path, 1 for a directory, 0 for anything else.
# lstat: a symbolic link is never followed (§5.3).
def kind_at(path: String) -> Int:
    try:
        var st = lstat(path)
        if (st.st_mode & 0o170000) == 0o040000:
            return 1
        return 0
    except:
        return -1


def write_file(path: String, data: List[UInt8], mode: Int) raises:
    var p = path
    # O_WRONLY | O_CREAT | O_EXCL: never writes through an entry that appeared after removal.
    var fd = external_call["open", c_int](p.as_c_string_span(), c_int(0o301), c_int(0o666))
    if fd < 0:
        raise Error(path + ": cannot create file")
    var off = 0
    while off < len(data):
        var n = external_call["write", c_ssize_t](Int(fd), data.unsafe_ptr().unsafe_offset(off), len(data) - off)
        if n <= 0:
            _ = external_call["close", c_int](fd)
            raise Error(path + ": write failed")
        off += Int(n)
    if mode >= 0:
        if external_call["fchmod", c_int](fd, c_int(mode)) != 0:
            _ = external_call["close", c_int](fd)
            raise Error(path + ": chmod failed")
    if external_call["close", c_int](fd) != 0:
        raise Error(path + ": close failed")


def apply(p: Parser, dir: String, idx: Int, script_mode: Int) raises:
    ref node = p.nodes[idx]
    # Members in ascending order of the UTF-8 bytes of their names, like the reference.
    var order = List[Int]()
    for i in range(len(node.names)):
        var j = len(order)
        order.append(i)
        while j > 0 and less(node.names[i], node.names[order[j - 1]]):
            order[j] = order[j - 1]
            j -= 1
        order[j] = i
    for oi in range(len(order)):
        var i = order[oi]
        var path = dir + "/" + bytes_str(node.names[i])
        ref child = p.nodes[node.kids[i]]
        var existing = kind_at(path)
        if child.kind == OBJECT:
            if existing != 1:
                if existing == 0:
                    unlink(path)
                mkdir(path, 0o777)
            apply(p, path, node.kids[i], script_mode)
            continue
        # §5.4: a directory in the way of a non-object is an error.
        if existing == 1:
            raise Error(path + ": a directory is in the way")
        if existing == 0:
            unlink(path)
        if child.kind == FILE:
            write_file(path, child.data, -1)
        elif child.kind == SCRIPT:
            write_file(path, child.data, script_mode)
        else:
            symlink(bytes_str(child.data), path)


def run() raises:
    var src = read_stdin()
    check_utf8(src)
    var p = Parser(src^)
    # A byte order mark at the start may be ignored (§3).
    if len(p.src) >= 3 and p.src[0] == UInt8(0xEF) and p.src[1] == UInt8(0xBB) and p.src[2] == UInt8(0xBF):
        p.pos = 3
    p.ws()
    if p.peek() != 0x7B:
        if p.peek() < 0:
            p.fail("empty input")
        raise Error("the root of the document must be an object")
    var root = p.object(0)
    p.ws()
    if p.pos != len(p.src):
        p.fail("trailing data")
    # Script mode: 0666 & ~umask, plus a+x (§4.4.2).
    var mask = Int(external_call["umask", UInt32](UInt32(0)))
    _ = external_call["umask", UInt32](UInt32(mask))
    apply(p, ".", root, (0o666 & ~mask) | 0o111)


def main():
    var stderr = FileDescriptor(2)
    if len(argv()) > 1:
        print("usage: json2dir < document.json", file=stderr)
        exit(2)
    try:
        run()
    except e:
        print("json2dir:", e, file=stderr)
        exit(1)
