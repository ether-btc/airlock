# Copyright 2026 Otsoa Dubief
# SPDX-License-Identifier: Apache-2.0
"""Defenses that do not depend on reading commands: secrets that never leave, a canary in the agent's context,
destinations named by untrusted content, and Unicode that hides what a command really is.

Commands are judged as the shell reads them (raw text). These checks look at every form a value can take on its way
out: raw, Unicode-folded, URL-decoded, base64-decoded, string concatenations joined, dict keys included.
Pure functions; the plugin (__init__.py) keeps the per-session state they need.
"""
from __future__ import annotations

import base64
import binascii
import functools
import html
import re
import unicodedata
from urllib.parse import unquote, urlparse

from . import shell

# --- Unicode ----------------------------------------------------------------------------------------------------

# Characters that render as nothing: inside a program name they make "git" something else.
ZERO_WIDTH_CHARS = ("\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b-\u200d\u2060-\u2064\u3164\ufeff\uffa0"
                    "\ufe00-\ufe0f")
ZERO_WIDTH = re.compile(f"[{ZERO_WIDTH_CHARS}]")
# Characters that reorder or hide text: the command a person approves would not be the command that runs.
# Never legitimate in a command, wherever they are (tags hide text, bidi controls reorder it).
REORDERING_CHARS = "\u202a-\u202e\u2066-\u2069\U000e0000-\U000e007f"
REORDERING = re.compile(f"[{REORDERING_CHARS}]")
INVISIBLE = re.compile(f"[{ZERO_WIDTH_CHARS}{REORDERING_CHARS}\U000e0100-\U000e01ef]")
# Syntax that makes what follows look inert to a reader: a quote, a backtick, a comment, an escape. A fullwidth one is
# a plain character to the shell, so the real `;` after ＂ runs while the reader sees it quoted.
HIDING = set("\"'`#\\")


DOTS = str.maketrans({"\u3002": ".", "\uff61": ".", "\uff0e": ".", "\u2024": ".", "\ufe52": "."})


def clean(text: str) -> str:
    """Text as a reader sees it: compatibility forms folded (NFKC: fullwidth letters, ligatures), ideographic and
    other dots read as dots (as IDN-aware tools do in host names), invisible or direction-changing characters removed.
    For scanning values, never for judging what the shell will run."""
    return INVISIBLE.sub("", unicodedata.normalize("NFKC", text).translate(DOTS))


def disguised_command(raw: str, program_words: list):
    """Reason if a command uses Unicode to look different from what the shell runs, else None:
    reordering or tag characters anywhere; zero-width characters inside a program name; a compatibility character
    (fullwidth quote, backtick, hash) that a reader takes for shell syntax the shell itself does not see."""
    if REORDERING.search(raw or ""):
        return "characters that reorder or hide text in a command (what you would approve is not what runs)"
    for w in program_words:
        if ZERO_WIDTH.search(w or ""):
            return "invisible characters inside a program name"
    for ch in set(raw or ""):
        if ord(ch) > 127:
            folded = unicodedata.normalize("NFKC", ch)
            # ＂ ＇ ｀ ＃ ＼: they hide what follows. Ordinary text folds too (… ‼ and the CJK ，：！), into nothing that
            # hides anything.
            if folded in HIDING:
                return f"a compatibility character ({ch!r} reads as {folded!r}) that hides shell syntax"
    return lookalike_program(program_words)


def lookalike_program(words: list):
    """Reason if the program a command runs is spelled with lookalike letters (``ɡit``, Cyrillic ``сurl``,
    fullwidth ``ｇｉｔ``): a rule written for the real name cannot see it. None otherwise. A name written in one other
    script (``./отчёт.sh``, ``./αρχείο.sh``) is someone's language, not a disguise: only a name that mixes it with
    Latin letters is, or one with letters nobody names a file with (IPA, fullwidth, mathematical)."""
    for w in words:
        for run in re.findall(r"[^\W\d_]+", w or ""):             # a run of letters: отчёт and sh in ./отчёт.sh
            odd = [ch for ch in run if _lookalike(ch)]
            if odd and (any(ch.isascii() for ch in run) or any(_never_ordinary(ch) for ch in odd)):
                return f"a program name spelled with lookalike letters ({w[:40]})"
    return None


def _never_ordinary(ch):
    """IPA, phonetic, fullwidth and mathematical letters: no language writes file names with them."""
    name = unicodedata.name(ch, "")
    return 0x0250 <= ord(ch) <= 0x02AF or 0x1D00 <= ord(ch) <= 0x1DBF or "FULLWIDTH" in name or \
        "MATHEMATICAL" in name


def _lookalike(ch):
    """A letter from a script that imitates Latin letters. Accented Latin letters (é, ñ) are ordinary: a script
    called ./café.sh is not a disguise."""
    if ord(ch) < 128 or not unicodedata.category(ch).startswith("L"):
        return False
    if 0x0250 <= ord(ch) <= 0x02AF or 0x1D00 <= ord(ch) <= 0x1DBF:      # IPA and phonetic extensions (ɡ, ᴄ)
        return True
    name = unicodedata.name(ch, "")
    return any(s in name for s in ("CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE", "MATHEMATICAL", "COPTIC", "FULLWIDTH",
                                   "DOTLESS"))


# --- Every form a value takes -------------------------------------------------------------------------------------

B64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{20,}={0,2}")
HEX_TOKEN = re.compile(r"\b(?:[0-9a-fA-F]{2}){12,}\b")
QUOTE_JOIN = re.compile(r"[\"']\s*(?:\+\s*)?[\"']")      # "ghp_" "abc", 'AKIA' + 'X'
ESCAPE = re.compile(r"\\(?:u([0-9a-fA-F]{4})|([nrt\"\\/]))")
MAX_VIEW = 400_000


ESCAPED = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\", "/": "/"}


def unescape(text: str) -> str:
    """JSON and C escapes read as what they stand for (an escaped newline must not glue two words together)."""
    return ESCAPE.sub(lambda m: chr(int(m.group(1), 16)) if m.group(1) else ESCAPED[m.group(2)], text)


def views(texts, squeeze: bool = False) -> list:
    """Every form of the texts worth scanning: raw, folded (NFKC, invisibles removed), URL- and HTML-decoded, escapes
    decoded, concatenations joined (``"ghp_" "abc"``, ``'AKIA'+'X'``), and the content of base64 or hex tokens, decoded
    twice (a value encoded, then encoded again). Every token is decoded: a cap would let padding push a value past it,
    and the tokens of a text are never longer than the text. squeeze=True adds short texts with their whitespace
    removed: for the canary only, as words glued together look like keys (``sk-SK locale settings for Windows 11``)."""
    return list(_views(tuple(str(t) for t in texts), squeeze))


@functools.lru_cache(maxsize=8)
def _views(texts: tuple, squeeze: bool) -> tuple:
    out = []
    for t in texts:
        t = str(t)[:MAX_VIEW]
        subst = shell.substitute_vars(t)
        # As the shell reads it too: quotes and backslashes dropped (ghp_\aB…), unset variables empty (ghp_${E}aB…).
        forms = dict.fromkeys([t, clean(t), subst, shell.unmask(t), shell.EMPTY_VAR.sub("", subst)])
        for f in list(forms):
            more = [unquote(unquote(f)), html.unescape(f).replace("\\/", "/"), QUOTE_JOIN.sub("", f)]
            if "\\" in f:
                more.append(unescape(f))
            if squeeze and len(more[2]) < 4000:
                more.append(re.sub(r"\s+", "", more[2]))
            forms.update(dict.fromkeys(more))
        new = list(forms)
        for _ in range(2):
            decoded = {}
            for f in new:
                for tok in B64_TOKEN.findall(f):
                    # /a/<base64>: the slash of a path is a base64 character too, so the parts are read as well
                    parts = [p for p in tok.split("/") if len(p) >= 16] if "/" in tok else []
                    for part in [tok] + parts:
                        dec = _b64(part)
                        if dec:
                            decoded[dec] = None
                for tok in HEX_TOKEN.findall(f):
                    try:
                        decoded[binascii.unhexlify(tok).decode("utf-8", "ignore")] = None
                    except (binascii.Error, ValueError):
                        pass
            new = [d for d in decoded if d not in forms]
            forms.update(dict.fromkeys(new))
        out.extend(x for x in forms if x)
    return tuple(dict.fromkeys(out))


def new_decision():
    """Forget the views of the previous call: they are kept for one decision only (several checks read them)."""
    _views.cache_clear()


def _b64(tok):
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = fn(tok + "=" * (-len(tok) % 4))
        except (binascii.Error, ValueError):
            continue
        text = raw.decode("utf-8", "ignore")
        if text and sum(ch.isprintable() or ch in "\n\r\t" for ch in text) / len(text) > 0.9:
            return text
    return None


# --- Secrets ----------------------------------------------------------------------------------------------------

# Formats with a distinctive prefix or shape, so ordinary text does not match. (name, pattern, strong): a weak format
# (JSON web tokens, often short-lived and sent on purpose) asks the owner instead of blocking.
SECRET_PATTERNS = [
    ("private key", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----\s*[A-Za-z0-9+/=]{40,}"), True),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)(?![0-9A-Z]*EXAMPLE)[0-9A-Z]{16}\b"), True),
    ("GitHub token", re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"), True),
    ("GitLab token", re.compile(r"glpat-[A-Za-z0-9_-]{20,}"), True),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{30,}"), True),
    ("OpenRouter API key", re.compile(r"\bsk-or-v1-[0-9a-f]{64}\b"), True),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}"), True),
    ("DeepSeek API key", re.compile(r"\bsk-[0-9a-f]{32}\b"), True),
    ("Groq API key", re.compile(r"\bgsk_[A-Za-z0-9]{40,}\b"), True),
    ("xAI API key", re.compile(r"\bxai-[A-Za-z0-9]{40,}\b"), True),
    ("Perplexity API key", re.compile(r"\bpplx-[A-Za-z0-9]{40,}\b"), True),
    ("Slack token", re.compile(r"xox[abposr]-[A-Za-z0-9-]{10,}"), True),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"), True),
    ("Stripe secret key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}"), True),
    ("Telegram bot token", re.compile(r"\b\d{8,10}:AA[0-9A-Za-z_-]{33}(?![0-9A-Za-z_-])"), True),
    ("Hugging Face token", re.compile(r"hf_[A-Za-z0-9]{34,}\b"), True),
    ("npm token", re.compile(r"npm_[A-Za-z0-9]{36}\b"), True),
    ("JSON web token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), False),
]


SECRET_HINT = re.compile(r"PRIVATE KEY|AKIA|ASIA|gh[pousr]_|github_pat_|glpat-|sk-|gsk_|xai-|pplx-|xox|AIza|_live_|:AA|"
                         r"hf_|npm_|eyJ")


def _key_shaped(name, token):
    """An OpenAI key mixes digits and capitals; a branch name such as sk-feature-add-user-auth does not (OpenRouter
    and DeepSeek keys, lower-case hex, have patterns of their own)."""
    return name != "OpenAI API key" or bool(re.search(r"[0-9]", token) and re.search(r"[A-Z]", token))


def find_secret(texts):
    """(name, strong) of the secret found in any form of the texts, a strong format before a weak one (a JWT next to a
    provider key must not lower the decision), else None."""
    weak = None
    for v in views(texts):
        if not SECRET_HINT.search(v):
            continue
        for name, rx, strong in SECRET_PATTERNS:
            if any(_key_shaped(name, m.group(0)) for m in rx.finditer(v)):
                if strong:
                    return name, strong
                weak = weak or (name, strong)
    return weak


# --- Canary -------------------------------------------------------------------------------------------------------

def carries_canary(texts, marker: str) -> bool:
    """True if any form of the texts holds 12 consecutive characters of the marker's random part, in any case,
    reversed, or with separators inserted (base64 and hex forms are decoded by views)."""
    if not marker:
        return False
    core = marker.split("-", 1)[-1].lower()
    windows = {core[i:i + 12] for i in range(len(core) - 11)}
    # Once separators are stripped, unrelated text can line up by chance: a longer stretch is required there.
    long_windows = {core[i:i + 18] for i in range(len(core) - 17)}
    for v in views(texts, squeeze=True):
        low = v.lower()
        hexonly = re.sub(r"[^0-9a-f]", "", low)
        if any(w in low or w in low[::-1] for w in windows) or \
                any(w in hexonly or w in hexonly[::-1] for w in long_windows):
            return True
    return False


# --- Destinations named by untrusted content --------------------------------------------------------------------

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24})\b")
URL_HOST = re.compile(r"\b(?:https?|wss?|ftp|sftp|ssh|git\+https?|git)://(?:[^@/?#\s\"'<>]+@)?"
                      r"([\w.-]+\.[^\W\d_]{2,24}|\d{1,3}(?:\.\d{1,3}){3})", re.I)
BARE_HOST = re.compile(r"(?<![\w@./-])((?:[\w-]{1,63}\.)+([^\W\d_]{2,24}))"
                       r"(?=[/:\s\"'<>),;.!?*`\]。，、！？：；）」』】…”’»—–]|$)")            # CJK punctuation ends a host too
IPV4 = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
BARE_IP = re.compile(rf"(?<![\w.:/@-])({IPV4})(?![\w-]|\.\d)")
# user@host:path (scp, rsync, git). A plain user@host is a mail address, or ssh's argument (read with NET_PROGRAMS).
SSH_HOST = re.compile(r"(?:^|\s)[\w.-]+@((?:[\w-]+\.)+[^\W\d_]{2,24}|\d{1,3}(?:\.\d{1,3}){3})(?=:)")
# Programs whose host-like arguments are addresses (curl collector.example/up, scp f host:/tmp, dig x.example).
NET_PROGRAMS = re.compile(r"(?:^|\n|;|&&|\|\|?|\(|`)[ \t]*(?:[^\s;&|()`/]*/)*"     # separator, then a path
                          r"(dig|nslookup|host|drill|ping6?|traceroute|whois|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|"
                          r"rsync|curl|wget|http|https|xh|xhs|ftp|lftp)\b"
                          r"([^\n;&|]*)")
HOST_ARG = re.compile(r"(?:^|[\s@=\"'])((?:[\w-]{1,63}\.)+([^\W\d_]{2,24}))(?=[\s:/\"']|$)")
IP_ARG = re.compile(rf"(?:^|[\s@=\"'])({IPV4})(?=[\s:/\"']|$)")
# Real top-level domains a bare word must end with to count as a host (``socket.io`` yes, ``response.data`` no).
TLDS = set("""com org net io dev app ai co me info biz xyz online site tech cloud page link live store shop blog news
agency digital email services solutions systems software network company group today world zone space run sh
gg tv fm to ly cc ws in eu us uk de fr es it nl be ch at se no dk fi pl pt cz sk hu ro bg gr ie lu li is ee lv lt ru
ua by kz tr il ae sa qa pk bd lk np cn jp kr tw hk sg my th vn id ph au nz ca mx br ar cl pe ve za ng ke eg ma
tn dz test example invalid onion""".split())
# In a command's arguments these are files (curl -o install.sh), not hosts in Saint Helena, Poland or India.
FILE_EXTENSIONS = {"sh", "pl", "in"}
# On the side of what untrusted text names, a missing TLD lets an address through: every two-letter (country) code
# counts there, and these generic ones too. (Calls keep TLDS: `scp config.yaml host:` names no host config.yaml.)
NAMED_TLDS = TLDS | set("""top club icu buzz click work rest cyou cfd sbs bond lol quest monster fun life pro vip win
bid loan men mom host hosting uno best ltd ink kim party review stream trade date racing download accountant science
cricket faith gdn guru wiki website press center support social photos pics gallery studio design media money
finance cash credit exchange fund market trading bet casino games game play team tools technology consulting
management ventures partners international global city country earth land place mobi asia tel travel jobs museum
aero coop int edu gov mil cam dating love mov zip dad phd prof rsvp meme nexus channel digital domains feedback forum
homes lat loans mba ninja rocks scot surf today tours town training vision webcam wtf yoga""".split())
COMMON_HOSTS = {
    "github.com", "api.github.com", "raw.githubusercontent.com", "gist.github.com", "gitlab.com", "bitbucket.org",
    "google.com", "www.google.com", "googleapis.com", "youtube.com", "www.youtube.com", "wikipedia.org",
    "en.wikipedia.org", "stackoverflow.com", "pypi.org", "files.pythonhosted.org", "npmjs.com", "www.npmjs.com",
    "registry.npmjs.org", "docs.python.org", "developer.mozilla.org", "microsoft.com", "learn.microsoft.com",
    "apple.com", "developer.apple.com", "amazon.com", "cloudflare.com", "x.com", "twitter.com", "linkedin.com",
    "www.linkedin.com", "facebook.com", "instagram.com", "reddit.com", "www.reddit.com", "medium.com", "w3.org",
    "www.w3.org", "schema.org", "fonts.googleapis.com", "fonts.gstatic.com", "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net", "unpkg.com", "gravatar.com", "www.gravatar.com", "creativecommons.org",
}
# Mail providers: an address there names one person, never the whole provider.
MAIL_PROVIDERS = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "yahoo.fr",
                  "icloud.com", "me.com", "proton.me", "protonmail.com", "gmx.com", "gmx.fr", "orange.fr", "free.fr",
                  "sfr.fr", "laposte.net", "wanadoo.fr", "aol.com", "zoho.com", "fastmail.com", "mail.com"}


# Platforms where anyone gets a subdomain: attacker.vercel.app and exfil.vercel.app are two owners, not one site.
SHARED_SUFFIXES = {"vercel.app", "github.io", "gitlab.io", "netlify.app", "pages.dev", "workers.dev", "herokuapp.com",
                   "amazonaws.com", "cloudfront.net", "azurewebsites.net", "blob.core.windows.net", "appspot.com",
                   "web.app", "firebaseapp.com", "blogspot.com", "glitch.me", "onrender.com", "fly.dev", "railway.app",
                   "ngrok.io", "ngrok.app", "ngrok-free.app", "trycloudflare.com", "loca.lt", "repl.co", "replit.app",
                   "surge.sh", "deno.dev", "notion.site", "webflow.io", "wixsite.com", "myshopify.com",
                   "wordpress.com", "substack.com", "neocities.org", "pythonanywhere.com", "supabase.co",
                   "pipedream.net", "webhook.site", "requestcatcher.com", "beeceptor.com", "free.beeceptor.com"}


def hostname(url: str) -> str:
    """The host of a URL (or of a bare host[:port][/path]), lower-cased; "" when it cannot be parsed (https://[x)."""
    try:
        return (urlparse(url if "://" in url else "https://" + url).hostname or "").lower()
    except ValueError:
        return ""


def site(host: str) -> str:
    """The registrable part of a host, approximately: last two labels, three for co.uk-style suffixes, one more than
    a shared platform's suffix; an IPv4 address whole."""
    if re.fullmatch(IPV4, host or ""):
        return host                                     # an address is its own site (not its last two numbers)
    parts = host.lower().rstrip(".").split(".")
    for n in (4, 3, 2):
        if len(parts) > n and ".".join(parts[-n:]) in SHARED_SUFFIXES:
            return ".".join(parts[-n - 1:])
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac", "gov", "edu") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


EVERYWHERE = "*"            # in a session's destinations: a text named too many addresses to keep, all of them count


def named_in_content(text: str) -> list:
    """Hosts, IPv4 addresses and e-mail addresses an untrusted text names, in order of appearance (lower-cased). HTML
    entities, escaped slashes and JSON escapes are decoded first (a tool result is JSON: an escaped newline must not
    glue the next word to an address). The text is read folded (NFKC, invisible characters out: collec<ZWSP>tor,
    fullwidth dots) twice, with and without ideographic dots as dots (collector。evil。test, but also the 。 that ends
    a sentence). A mail provider's domain is never kept for an address there."""
    text = "/".join(part.rstrip("\\") for part in unescape(html.unescape(text or "")).split("/"))
    folded = INVISIBLE.sub("", unicodedata.normalize("NFKC", text))
    found = []
    for text in dict.fromkeys([folded, folded.translate(DOTS)]):
        for m in EMAIL.finditer(text):
            found.append(m.group(0).lower())
            if m.group(1).lower() not in MAIL_PROVIDERS:
                found.append(m.group(1).lower())
        for m in URL_HOST.finditer(text):
            found.append(m.group(1).lower().rstrip("."))
        for m in BARE_HOST.finditer(text):
            if _real_tld(m.group(2), named=True):
                found.append(m.group(1).lower().rstrip("."))
        found += BARE_IP.findall(text)
    return list(dict.fromkeys(found))


def _real_tld(tld: str, named: bool = False) -> bool:
    """A top-level domain from the list, or an internationalized one (non-ASCII letters, as in .рф). With named=True
    (what untrusted text names), any two-letter code and NAMED_TLDS too."""
    tld = tld.lower()
    return tld in TLDS or not tld.isascii() or (named and (len(tld) == 2 or tld in NAMED_TLDS))


def destinations(text: str, source: str, local, own=(), limit: int = 5000) -> list:
    """Destinations an untrusted text names, minus the sites of the documents themselves (the source's and those of
    `own`, e.g. the results of a search), common hosts and what `local` clears (loopback, trusted domains). A text
    that names more than `limit` of them (a flood meant to push the real one out of memory) makes every address
    count: [EVERYWHERE]."""
    m = re.search(r"https?://\S+", source or "")
    sites = {site(h) for h in [hostname(m.group(0)) if m else "", *own] if h}
    new = [d for d in named_in_content(text)
           if d not in COMMON_HOSTS and not local(d) and site(d.rpartition("@")[2]) not in sites]
    return [EVERYWHERE] if len(new) > limit else new


def merge(seen: list, new: list, limit: int = 5000) -> list:
    """`seen` plus `new`, the oldest dropped first past `limit` (never one of `new`)."""
    out = [d for d in seen if d not in new] + new
    return [EVERYWHERE] if EVERYWHERE in out else out[-max(limit, len(new)):]


def call_addresses(texts) -> list:
    """Addresses a call would reach: URL hosts, e-mail addresses, user@host targets (ssh, scp, git), and the hosts of
    network commands. Words in a commit message or prose are not addresses."""
    found = []
    for v in views(texts):
        found += [m.group(1).lower().rstrip(".") for m in URL_HOST.finditer(v)]
        found += [m.group(0).lower() for m in EMAIL.finditer(v)]
        found += [m.group(1).lower() for m in SSH_HOST.finditer(v)]
        for prog in NET_PROGRAMS.finditer(v):
            found += [m.group(1).lower().rstrip(".") for m in HOST_ARG.finditer(prog.group(2))
                      if _real_tld(m.group(2)) and m.group(2).lower() not in FILE_EXTENSIONS]
            found += IP_ARG.findall(prog.group(2))
    return list(dict.fromkeys(found))


def named_destination(texts, seen, ignore=lambda host: False):
    """(address, is_mail_recipient) for an address of the call that the untrusted content named, or a subdomain of a
    named host (any address, after a flood): a host before a mail recipient, the stricter of the two. Addresses that
    `ignore` clears (loopback, a domain trusted since) never count."""
    if not seen:
        return None
    seen = set(seen)
    hosts = [s for s in seen if "@" not in s]
    mail = None
    for a in call_addresses(texts):
        if ignore(a):
            continue
        named = a in seen or ("@" not in a and any(a.endswith("." + s) for s in hosts)) or \
            (EVERYWHERE in seen and a not in COMMON_HOSTS)
        if named and "@" not in a:
            return a, False
        if named:
            mail = mail or (a, True)
    return mail
