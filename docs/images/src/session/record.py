"""Records an interactive Hermes session in a pseudo-terminal as an asciicast v2 file.
Answers each step from a script of (wait-for regex, keys) pairs; idles out after a timeout."""
import json, os, pty, re, select, sys, time
import pyte

cast, cmd, steps = sys.argv[1], sys.argv[2:3], json.loads(sys.argv[3])
cols, rows = int(os.environ.get("COLS", "110")), int(os.environ.get("ROWS", "34"))
pid, fd = pty.fork()
if pid == 0:
    os.environ.update({"COLUMNS": str(cols), "LINES": str(rows), "TERM": "xterm-256color"})
    os.execvp("/bin/sh", ["sh", "-c", cmd[0]])
import fcntl, struct, termios
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
t0, buf, out = time.time(), "", open(cast, "w")
screen = pyte.Screen(cols, rows); stream = pyte.Stream(screen)
out.write(json.dumps({"version": 2, "width": cols, "height": rows, "timestamp": int(t0)}) + "\n")
step, last, seen = 0, time.time(), None
while True:
    r, _, _ = select.select([fd], [], [], 0.5)
    if r:
        try:
            data = os.read(fd, 65536)
        except OSError:
            break
        if not data:
            break
        s = data.decode("utf-8", "replace")
        out.write(json.dumps([round(time.time() - t0, 3), "o", s]) + "\n")
        buf += s
        stream.feed(s)
        last = time.time()
    if step < len(steps):
        pat, keys, delay = steps[step]
        if seen is None and re.search(pat, "\n".join(screen.display)):
            seen = time.time()
        if seen is not None and time.time() - seen > delay:
            for k in keys:
                os.write(fd, k.encode())
                time.sleep(0.15)
            seen, step = None, step + 1
    if time.time() - last > float(os.environ.get("IDLE", "240")) or time.time() - t0 > float(os.environ.get("MAXT", "600")):
        break
out.close()
