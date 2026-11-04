// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aeroprove/aeroprove/internal/atomicfile"
)

// The auditd tail.
//
// auditd writes a machine's own record of what its kernel did, as text:
// several lines per event, all carrying the same serial, each line one
// record type. An execve is a SYSCALL line (who, what binary, which tty)
// beside an EXECVE line (the argv); a connect is a SYSCALL beside a
// SOCKADDR (where). Reading either line alone is reading half the event, so
// the tailer reassembles groups by serial and emits one record per group,
// shaped exactly as the auditd/events mapping in internal/source reads it:
// a "@timestamp", a "host", a "type", and the fields that mapping keeps
// (exe, auid, uid, res, key, comm, tty). Rules written against that source
// read collector events unchanged, which is the whole point of reusing the
// mapping instead of inventing a second one.

// auditRecordTypes is the set whose groups become records. Everything else
// auditd writes — DAEMON_START, SERVICE_START, CONFIG_CHANGE, and the record
// types that only ever ride beside one of these — is not evidence this
// recorder ships.
var auditRecordTypes = map[string]bool{
	"EXECVE": true, "SYSCALL": true, "USER_CMD": true,
	"USER_LOGIN": true, "USER_AUTH": true,
}

// Assembler turns auditd lines into complete event records.
//
// auditd writes every record of one event contiguously, so a serial
// different from the last one means the last group is finished. What is
// still held when the log goes quiet stays held: a group flushed before its
// last line had arrived would be half an event, and half an event is worse
// than a late one.
type Assembler struct {
	serial string
	group  map[string]string
	// kinds is which record types the group has, in the order they arrived.
	kinds []string
	// host is the node= the lines named, for a group whose own lines said
	// none — and for the record a group with no node at all falls back to.
	host string
}

// Feed gives the assembler one line and returns whatever groups it
// completed. Lines that are not auditd records are skipped: an audit log
// mixes in an occasional odd line, and a recorder that died on one would be
// a recorder an attacker could aim.
func (a *Assembler) Feed(line string) []map[string]any {
	head, fields, serial, ok := parseAuditLine(line)
	if !ok {
		return nil
	}
	typ := head["type"]
	if a.serial != "" && serial != a.serial {
		out := a.take()
		a.begin(serial, head, fields, typ)
		return out
	}
	if a.serial == "" {
		a.begin(serial, head, fields, typ)
		return nil
	}
	// The same event, continued: merge, with what arrived first winning —
	// for the fields both record types carry, the SYSCALL line's own are
	// the authoritative ones, and it arrives first.
	for k, v := range fields {
		if _, exists := a.group[k]; !exists {
			a.group[k] = v
		}
	}
	if typ != "" {
		a.kinds = append(a.kinds, typ)
	}
	return nil
}

func (a *Assembler) begin(serial string, head, fields map[string]string, typ string) {
	a.serial = serial
	a.group = fields
	a.kinds = nil
	if typ != "" {
		a.kinds = []string{typ}
	}
	if n := head["node"]; n != "" {
		a.host = n
	}
}

// take flushes the held group as one record, and forgets it.
func (a *Assembler) take() []map[string]any {
	rec := a.record()
	a.serial, a.group, a.kinds = "", nil, nil
	if rec == nil {
		return nil
	}
	return []map[string]any{rec}
}

// Flush emits whatever is held. Called at shutdown: evidence held in memory
// is evidence the spool does not have, and a group that was never finished
// is still more than nothing.
func (a *Assembler) Flush() []map[string]any {
	if a.serial == "" {
		return nil
	}
	return a.take()
}

// record is the held group as one auditd/events record, or nil for a group
// this recorder does not ship.
func (a *Assembler) record() map[string]any {
	if a.group == nil {
		return nil
	}
	typ := ""
	for _, k := range []string{"EXECVE", "SYSCALL", "USER_CMD", "USER_LOGIN", "USER_AUTH"} {
		if hasKind(a.kinds, k) {
			typ = k
			break
		}
	}
	if typ == "" || !auditRecordTypes[typ] {
		return nil
	}
	secs, ms, _ := splitStamp(a.group["@stamp"])
	when := time.Unix(secs, ms*int64(time.Millisecond)).UTC()
	out := map[string]string{
		"type":       typ,
		"@timestamp": when.Format("2006-01-02T15:04:05.000Z07:00"),
		"host":       a.group["node"],
	}
	if out["host"] == "" {
		out["host"] = a.host
	}
	// The fields the mapping keeps, plus the ones an analyst reading the
	// raw event wants beside them.
	for _, k := range []string{"auid", "uid", "exe", "comm", "tty", "key",
		"ses", "pid", "ppid", "res", "addr", "port", "syscall", "path",
		"cwd", "cmd"} {
		if v := a.group[k]; v != "" {
			out[k] = v
		}
	}
	// USER_CMD writes terminal= where SYSCALL writes tty=; the mapping keeps
	// tty, so that is the spelling that survives.
	if out["tty"] == "" {
		out["tty"] = a.group["terminal"]
	}
	// A connect's SOCKADDR rode along as saddr hex; the record says the
	// address a person and a rule can read.
	if out["addr"] == "" && a.group["saddr"] != "" {
		addr, port := decodeSockAddr(a.group["saddr"])
		if addr != "" {
			out["addr"], out["port"] = addr, port
		}
	}
	// res in the mapping's vocabulary: auditd's SYSCALL lines say
	// success=yes|no and its USER_* lines say res=success|failed. One field,
	// both spellings normalised, because a rule matching res=success must
	// mean the same thing whichever audit rule produced the line.
	switch {
	case out["res"] != "":
	case strings.EqualFold(a.group["success"], "yes"):
		out["res"] = "success"
	case strings.EqualFold(a.group["success"], "no"):
		out["res"] = "failed"
	}
	if argv := a.argv(); argv != "" {
		out["argv"] = argv
	}
	if out["syscall"] != "" {
		out["syscall"] = syscallName(a.group["arch"], out["syscall"])
	}
	any := make(map[string]any, len(out))
	for k, v := range out {
		any[k] = v
	}
	return any
}

// argv is the EXECVE record's arguments, a0..aN joined. The SYSCALL line's
// own a0..a3 are kernel pointers and are dropped rather than kept beside the
// arguments, because two fields named a0 in one record is a lie either way.
func (a *Assembler) argv() string {
	if !hasKind(a.kinds, "EXECVE") {
		return ""
	}
	idx := []int{}
	for k := range a.group {
		if len(k) > 1 && k[0] == 'a' {
			if n, err := strconv.Atoi(k[1:]); err == nil && n >= 0 {
				idx = append(idx, n)
			}
		}
	}
	if len(idx) == 0 {
		return ""
	}
	sort.Ints(idx)
	parts := make([]string, 0, len(idx))
	for _, n := range idx {
		if v := a.group["a"+strconv.Itoa(n)]; v != "" {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, " ")
}

func hasKind(kinds []string, k string) bool {
	for _, s := range kinds {
		if s == k {
			return true
		}
	}
	return false
}

// syscallName names the numbers this recorder claims to know, per
// architecture, and leaves every other number as it arrived. Naming a
// syscall wrong is worse than not naming it: "connect" in a record is a
// claim a detection hangs on.
var syscallNames = map[string]map[string]string{
	// AUDIT_ARCH_X86_64
	"c000003e": {"42": "connect", "59": "execve", "322": "execveat"},
	// AUDIT_ARCH_AARCH64
	"c00000b7": {"203": "connect", "221": "execve", "281": "execveat"},
}

func syscallName(arch, num string) string {
	if names, ok := syscallNames[strings.ToLower(arch)]; ok {
		if n, ok := names[num]; ok {
			return n
		}
	}
	return num
}

// parseAuditLine splits one auditd line into its header fields, its record
// fields and its serial.
//
//	node=build01 type=SYSCALL msg=audit(1761401760.512:4217): arch=c000003e …
//
// Values are double-quoted, single-quoted (the nested msg='cwd=… cmd=…'),
// bracketed like (null), or bare. The single-quoted msg is re-parsed for the
// fields inside it, because USER_CMD keeps what it cares about there.
func parseAuditLine(line string) (head, fields map[string]string, serial string, ok bool) {
	line = strings.TrimSuffix(line, "\n")
	open := strings.Index(line, "msg=audit(")
	if open < 0 {
		return nil, nil, "", false
	}
	head = parseFields(line[:open])
	rest := line[open+len("msg=audit("):]
	closing := strings.Index(rest, ")")
	if closing < 0 {
		return nil, nil, "", false
	}
	stamp := rest[:closing]
	secs, ms, serial := splitStamp(stamp)
	if secs == 0 && ms == 0 && serial == "" {
		return nil, nil, "", false
	}
	fields = parseFields(rest[closing+2:])
	fields["@stamp"] = stamp
	if cmd := fields["msg"]; cmd != "" {
		inner := parseFields(cmd)
		for k, v := range inner {
			if _, exists := fields[k]; !exists {
				fields[k] = v
			}
		}
		delete(fields, "msg")
	}
	return head, fields, serial, true
}

// splitStamp is "seconds.milliseconds:serial".
func splitStamp(stamp string) (secs, ms int64, serial string) {
	dot := strings.Index(stamp, ".")
	if dot < 0 {
		dot = 0
	}
	colon := strings.LastIndex(stamp, ":")
	if colon < 0 {
		colon = len(stamp)
	}
	secs, _ = strconv.ParseInt(stamp[:dot], 10, 64)
	ms, _ = strconv.ParseInt(stamp[dot+1:colon], 10, 64)
	return secs, ms, stamp[colon+1:]
}

// parseFields reads auditd's key=value pairs. A quoted value may contain
// spaces; a bracketed value like (null) is kept as empty — auditd writes
// (null) for "no value", and the word "(null)" sitting in an event field is
// a value nobody wrote.
func parseFields(s string) map[string]string {
	out := map[string]string{}
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		eq := strings.IndexByte(s[i:], '=')
		if eq < 0 {
			break
		}
		key := s[i : i+eq]
		i += eq + 1
		if key == "" {
			continue
		}
		if i >= len(s) {
			out[key] = ""
			break
		}
		var val string
		switch s[i] {
		case '"', '\'':
			quote := s[i]
			end := strings.IndexByte(s[i+1:], quote)
			if end < 0 {
				out[key] = s[i+1:]
				i = len(s)
				continue
			}
			val = s[i+1 : i+1+end]
			i += end + 2
		case '(':
			end := strings.IndexByte(s[i:], ')')
			if end < 0 {
				out[key] = s[i+1:]
				i = len(s)
				continue
			}
			val = ""
			i += end + 1
		default:
			end := strings.IndexAny(s[i:], " \t")
			if end < 0 {
				end = len(s) - i
			}
			val = s[i : i+end]
			i += end
		}
		out[key] = val
	}
	return out
}

// decodeSockAddr turns a SOCKADDR record's saddr hex into an address and
// port. The struct is the kernel's own sockaddr: a two-byte family in host
// byte order, then the address family's payload in network byte order.
// Anything this does not recognise is left as the hex it arrived as.
func decodeSockAddr(saddr string) (addr, port string) {
	b, err := hex.DecodeString(strings.TrimPrefix(saddr, "0x"))
	if err != nil {
		return "", ""
	}
	if len(b) < 4 {
		return "", ""
	}
	family := uint16(b[0]) | uint16(b[1])<<8
	p := int(b[2])<<8 | int(b[3])
	switch family {
	case 2: // AF_INET
		if len(b) >= 8 {
			return net.IP(b[4:8]).String(), strconv.Itoa(p)
		}
	case 10: // AF_INET6
		if len(b) >= 20 {
			return net.IP(b[4:20]).String(), strconv.Itoa(p)
		}
	case 1: // AF_UNIX
		if n := strings.IndexByte(string(b[4:]), 0); n >= 0 {
			return string(b[4 : 4+n]), ""
		}
		return string(b[4:]), ""
	}
	return "", ""
}

// Tailer follows one auditd log, remembering where it got to.
//
// The position file (offset and size) is the resume story: a restarted
// collector rereads nothing and skips nothing. Rotation — auditd renames the
// live file to audit.log.1 and a new file appears under the old name — is
// detected by the new file being smaller than the recorded offset, which is
// the ordinary shape of a fresh log. The one case size alone cannot catch is
// a rename straight onto a new file already larger than the old offset on a
// busy host; an inode would, but reading inodes means platform-specific
// syscalls, this program builds everywhere the server does, and the honest
// cost of that is written here rather than paid in build tags.
type Tailer struct {
	LogPath string
	// PosPath is the position file, inside the state directory.
	PosPath string
	// Host is what records say when the log's own node= says nothing.
	Host string
	// From is "end" or "start": where a first run with no position begins.
	From string
	// Logf is told the rare events a person operating this needs to see.
	Logf func(string, ...any)

	pos   auditPosition
	ready bool
	asm   Assembler
}

type auditPosition struct {
	Offset int64 `json:"offset"`
	Size   int64 `json:"size"`
}

// pollRead caps one poll's read. A collector that read an unbounded log
// growth in one go would be a collector with an unbounded heap, and the
// unbounded thing an attacker can aim at a recorder is the recorder.
const pollRead = 8 << 20

// Poll reads what is new and returns the records it completed. The log not
// existing is not an error: auditd not being installed yet is a state, and
// the collector's job is to keep watching for it.
func (t *Tailer) Poll() ([]map[string]any, error) {
	info, err := os.Stat(t.LogPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if !t.ready {
		t.ready = true
		// No position saved: join the log where it is (the default — a
		// fresh recorder does not replay weeks of history) or at its top,
		// per the config. A saved position then wins over both, whichever
		// made it.
		t.pos.Offset = info.Size()
		if t.From == "start" {
			t.pos.Offset = 0
		}
		_ = t.load()
	}
	if info.Size() < t.pos.Offset {
		t.logf("audit log %s is smaller than the recorded position "+
			"(rotated or truncated); reading the new file from the top",
			t.LogPath)
		t.pos.Offset = 0
	}
	if info.Size() == t.pos.Offset {
		return nil, t.save(info.Size())
	}
	f, err := os.Open(t.LogPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Seek(t.pos.Offset, io.SeekStart); err != nil {
		return nil, err
	}
	chunk := make([]byte, pollRead)
	n, rerr := io.ReadFull(f, chunk)
	if rerr != nil && rerr != io.ErrUnexpectedEOF && rerr != io.EOF {
		return nil, rerr
	}
	chunk = chunk[:n]
	// Only whole lines advance the position: a half-written trailing line is
	// the log's own "the kernel is still writing this", and consuming it
	// would splice a torn record into the middle of the next event.
	end := int64(len(chunk))
	if nl := strings.LastIndexByte(string(chunk), '\n'); nl >= 0 {
		end = int64(nl + 1)
	} else if n < pollRead {
		// The whole read is one incomplete line; hold it back entirely.
		return nil, t.save(info.Size())
	} else {
		// pollRead bytes and not one newline: a line longer than the read
		// cap, which is not a line auditd writes and not a thing a bounded
		// recorder buffers. Skipped, and said so.
		t.logf("audit log %s holds a line longer than %d bytes; skipping it",
			t.LogPath, pollRead)
	}
	var out []map[string]any
	for _, line := range strings.Split(string(chunk[:end]), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, t.asm.Feed(line)...)
	}
	t.pos.Offset += end
	if err := t.save(info.Size()); err != nil {
		return out, err
	}
	return out, nil
}

// Flush emits the group still held, if any. Called at shutdown: what is
// held is what the last poll read half of.
func (t *Tailer) Flush() []map[string]any {
	return t.asm.Flush()
}

func (t *Tailer) logf(format string, args ...any) {
	if t.Logf != nil {
		t.Logf(format, args...)
	}
}

func (t *Tailer) load() error {
	b, err := os.ReadFile(t.PosPath)
	if err != nil {
		return err
	}
	var p auditPosition
	if err := json.Unmarshal(b, &p); err != nil {
		return fmt.Errorf("%s is unreadable: %w", t.PosPath, err)
	}
	t.pos = p
	return nil
}

func (t *Tailer) save(size int64) error {
	t.pos.Size = size
	b, err := json.Marshal(t.pos)
	if err != nil {
		return err
	}
	return atomicfile.Write(t.PosPath, b, 0o600)
}
