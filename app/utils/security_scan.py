"""Static security scan of extracted Luanti content. Returns findings, never fails."""

import os
import re
from dataclasses import dataclass, asdict
from ipaddress import ip_address
from urllib.parse import urlparse

MAX_TEXT_FILE_BYTES = 1024 * 1024
MAX_FINDINGS = 200
MAX_SNIPPET = 200
SKIP_DIRS = {".git"}
TEXT_EXTS = {".lua", ".conf", ".txt", ".md", ".markdown", ".rst", ".cfg", ".json", ""}
NATIVE_RE = re.compile(r"\.(so|dll|exe|dylib|pyd)(\.\d+)*$", re.I)
BYTECODE_MAGIC = b"\x1bLua"

PRIORITY = [
	"native_binary", "lua_bytecode", "shell_exec",
	"insecure_env", "insecure_env_use", "http_api", "http_api_use",
	"secure_setting", "load_call", "dynamic_global", "hardcoded_host", "truncated",
]

GROUP_LABELS = {
	"load_call": "loadstring/load/dofile calls",
	"dynamic_global": "dynamic global access (_G[...], rawget(_G, ...), getfenv/setfenv)",
}

ALIAS_RE = re.compile(r"(?<![\w.])([A-Za-z_]\w*)\s*=\s*[\w.]*\brequest_(insecure_environment|http_api)\b")
INSECURE_RE = re.compile(r"\brequest_insecure_environment\b")
HTTP_RE = re.compile(r"\brequest_http_api\b|\bhttp_api\s*[.:]\s*fetch(?:_async(?:_get)?)?\b")
SHELL_RE = re.compile(r"\bos\s*\.\s*execute\b|\bio\s*\.\s*popen\b|\bpackage\s*\.\s*loadlib\b")
LOAD_RE = re.compile(r"(?<![\w.:])(?:loadstring|load|dofile|loadfile)\s*\(")
DYNAMIC_RE = re.compile(r"(?<!\w)_G\s*\[|\brawget\s*\(\s*_G\b|\bgetfenv\b|\bsetfenv\b")
SECURE_RE = re.compile(r"\bsecure\.(trusted_mods|http_mods|enable_security)\b")
URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")


@dataclass
class Finding:
	kind: str
	mod: str
	file: str
	line: int
	message: str
	snippet: str = ""

	def as_dict(self) -> dict:
		return asdict(self)


def _finding(kind: str, mod: str, file: str, line: int, message: str, text: str = "") -> Finding:
	text = text.strip()
	if len(text) > MAX_SNIPPET:
		text = text[:MAX_SNIPPET] + "..."
	return Finding(kind, mod, file, line, message, text)


def _hosts_in(line: str) -> list[str]:
	hosts = []
	for m in URL_RE.finditer(line):
		try:
			host = urlparse(m.group(0)).hostname
		except ValueError:
			continue
		if host:
			hosts.append(host.lower())
	for m in IP_RE.finditer(line):
		try:
			hosts.append(str(ip_address(m.group(0))))
		except ValueError:
			continue
	return hosts


def _scan_lua(mod: str, rel: str, lines: list[str]) -> list[Finding]:
	found = []
	code = [(i, t) for i, t in enumerate(lines, 1) if not t.lstrip().startswith("--")]

	aliases: dict[str, str] = {}
	for _, text in code:
		for m in ALIAS_RE.finditer(text):
			aliases[m.group(1)] = "insecure_env" if m.group(2) == "insecure_environment" else "http_api"

	use_res = {
		name: re.compile(r"(?<![\w.])" + re.escape(name) + r"\s*[.:]\s*(\w+(?:\s*\.\s*\w+)?)")
		for name in aliases
	}

	for i, text in code:
		reported = set()

		for name, kind in aliases.items():
			for m in use_res[name].finditer(text):
				use = re.sub(r"\s+", "", m.group(1))
				found.append(_finding(kind + "_use", mod, rel, i,
						f"Uses {kind.replace('_', ' ')} handle: {name}.{use}", text))
				reported.add(kind)

		if INSECURE_RE.search(text):
			found.append(_finding("insecure_env", mod, rel, i, "Requests the insecure environment", text))
		if "http_api" not in reported and HTTP_RE.search(text):
			found.append(_finding("http_api", mod, rel, i, "Uses the HTTP API", text))

		m = SHELL_RE.search(text)
		if m:
			found.append(_finding("shell_exec", mod, rel, i, "Uses " + re.sub(r"\s+", "", m.group(0)), text))

		if LOAD_RE.search(text):
			found.append(_finding("load_call", mod, rel, i, "", text))
		if DYNAMIC_RE.search(text):
			found.append(_finding("dynamic_global", mod, rel, i, "", text))

		for host in _hosts_in(text):
			found.append(_finding("hardcoded_host", mod, rel, i, f"Hardcoded host: {host}", text))

	return found


def _scan_file(path: str, rel: str, mod: str) -> list[Finding]:
	found = []

	if NATIVE_RE.search(os.path.basename(rel)):
		found.append(_finding("native_binary", mod, rel, 0, "Native binary file"))

	try:
		size = os.path.getsize(path)
		with open(path, "rb") as f:
			head = f.read(4)
			if head == BYTECODE_MAGIC:
				found.append(_finding("lua_bytecode", mod, rel, 0, "Precompiled Lua bytecode"))
				return found
			if size > MAX_TEXT_FILE_BYTES:
				return found
			data = head + f.read()
	except OSError:
		return found

	ext = os.path.splitext(rel)[1].lower()
	if ext not in TEXT_EXTS or b"\x00" in data[:1024]:
		return found

	lines = data.decode("utf-8", errors="replace").splitlines()

	for i, text in enumerate(lines, 1):
		for m in SECURE_RE.finditer(text):
			found.append(_finding("secure_setting", mod, rel, i, f"Mentions secure.{m.group(1)}", text))

	if ext == ".lua":
		found += _scan_lua(mod, rel, lines)

	return found


def _collapse(findings: list[Finding]) -> list[Finding]:
	result = []
	groups: dict[tuple[str, str], list[Finding]] = {}
	seen_hosts = set()

	for f in findings:
		if f.kind in GROUP_LABELS:
			groups.setdefault((f.kind, f.mod), []).append(f)
		elif f.kind == "hardcoded_host":
			if (f.mod, f.message) not in seen_hosts:
				seen_hosts.add((f.mod, f.message))
				result.append(f)
		else:
			result.append(f)

	for (kind, mod), hits in groups.items():
		first = ", ".join(f"{h.file}:{h.line}" for h in hits[:3])
		result.append(Finding(kind, mod, hits[0].file, hits[0].line,
				f"{len(hits)} {GROUP_LABELS[kind]} (first: {first})", hits[0].snippet))

	return result


def _rank_and_cap(findings: list[Finding]) -> list[Finding]:
	order = {k: n for n, k in enumerate(PRIORITY)}
	findings = sorted(findings, key=lambda f: (order.get(f.kind, len(order)), f.mod, f.file, f.line))

	if len(findings) > MAX_FINDINGS:
		extra = len(findings) - MAX_FINDINGS
		findings = findings[:MAX_FINDINGS]
		findings.append(_finding("truncated", ".", "", 0, f"Plus {extra} more findings not shown"))

	return findings


def scan_directory(root: str) -> list[Finding]:
	root = os.path.abspath(root)
	found = []
	mod_of_dir: dict[str, str] = {}

	for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
		dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

		rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
		if "mod.conf" in filenames:
			mod = rel_dir
		else:
			mod = mod_of_dir.get(os.path.dirname(rel_dir) or ".", ".")
		mod_of_dir[rel_dir] = mod

		for name in sorted(filenames):
			path = os.path.join(dirpath, name)
			if not os.path.islink(path):
				found += _scan_file(path, os.path.relpath(path, root).replace(os.sep, "/"), mod)

	return _rank_and_cap(_collapse(found))
