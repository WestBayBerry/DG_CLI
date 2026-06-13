const credentialUrlPattern = /\b([a-z][a-z0-9+.-]{0,31}:\/\/)([^/\s:@]+):([^/\s@]+)@/gi;
const authHeaderPattern = /\b(proxy-authorization|authorization):\s*[^\r\n]+/gi;
// Matches both KEY=value and colon-form (KEY: value, YAML) secret assignments;
// the separator and any opening quote are preserved in the replacement.
const tokenAssignmentPattern =
  /(?<![A-Za-z0-9])([A-Za-z0-9_-]*(?:secret[_-]key|access[_-]key|api[_-]key|token|password|secret))(\s*[:=]\s*)("?)([^\s"]+)/gi;
const npmrcAuthPattern = /(_authToken|_auth|_password)\s*=\s*("[^"]*"|[^\s;,]+)/gi;
const jsonSecretPattern =
  /("[A-Za-z0-9_.$-]*(?:secret[_-]key|access[_-]key|api[_-]key|token|password|secret)"\s*:\s*)"(?:[^"\\]|\\.)*"/gi;
const bearerPattern = /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/g;
// Bare tokens (not in URL userinfo or KEY=value form), by their published shape.
const knownTokenShapePattern =
  /\b(npm_[A-Za-z0-9]{36}|gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255}|pypi-[A-Za-z0-9_-]{20,}|glpat-[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_(?:live|test)_[A-Za-z0-9]{20,}|rk_live_[A-Za-z0-9]{20,}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}|xox[abdeprs]-[A-Za-z0-9-]{10,})\b/g;

export function redactSecrets(text: string): string {
  return text
    .replace(credentialUrlPattern, "$1<redacted>@")
    .replace(authHeaderPattern, (_match, header: string) => `${header}: <redacted>`)
    .replace(npmrcAuthPattern, "$1=<redacted>")
    .replace(jsonSecretPattern, '$1"<redacted>"')
    .replace(tokenAssignmentPattern, "$1$2$3<redacted>")
    .replace(bearerPattern, "Bearer <redacted>")
    .replace(knownTokenShapePattern, "<redacted>");
}

const STREAM_FLUSH_QUIET_MS = 80;
const SECRET_TAIL_SCAN_CHARS = 80;
const secretTailPattern =
  /(Bearer\s+[\w.~+/=-]*|npm_[A-Za-z0-9]*|gh[pousr]_[A-Za-z0-9]*|github_pat_[A-Za-z0-9_]*|pypi-[\w-]*|glpat-[\w-]*|hf_[A-Za-z0-9]*|AKIA[0-9A-Z]*|ASIA[0-9A-Z]*|AIza[\w-]*|sk_(?:live|test)_[A-Za-z0-9]*|rk_live_[A-Za-z0-9]*|sk-(?:proj-)?[\w-]*|xox[abdeprs]-[\w-]*|[\w-]*(?:_authToken|_auth|_password|secret[_-]key|access[_-]key|api[_-]key|token|password|secret)\s*[:=]\s*"?\S*|"[\w.$-]*(?:secret[_-]key|access[_-]key|api[_-]key|token|password|secret)"\s*:\s*"?[^"\n]*)$/i;

export interface StreamRedactor {
  readonly write: (chunk: string) => void;
  readonly flush: () => void;
}

export function createStreamRedactor(emit: (redacted: string) => void): StreamRedactor {
  let pending = "";
  let timer: NodeJS.Timeout | undefined;
  let tailHeldOnce = false;

  const clearTimer = (): void => {
    if (timer) {
      clearTimeout(timer);
      timer = undefined;
    }
  };

  const emitPending = (): void => {
    clearTimer();
    if (pending) {
      emit(redactSecrets(pending));
      pending = "";
    }
    tailHeldOnce = false;
  };

  const onQuietTimer = (): void => {
    timer = undefined;
    if (!pending) {
      tailHeldOnce = false;
      return;
    }
    const scanStart = Math.max(0, pending.length - SECRET_TAIL_SCAN_CHARS);
    const tailMatch = secretTailPattern.exec(pending.slice(scanStart));
    if (tailMatch && !tailHeldOnce) {
      const matchStart = scanStart + tailMatch.index;
      if (matchStart > 0) {
        emit(redactSecrets(pending.slice(0, matchStart)));
      }
      pending = pending.slice(matchStart);
      tailHeldOnce = true;
      timer = setTimeout(onQuietTimer, STREAM_FLUSH_QUIET_MS);
      timer.unref?.();
      return;
    }
    emit(redactSecrets(pending));
    pending = "";
    tailHeldOnce = false;
  };

  return {
    write(chunk: string): void {
      pending += chunk;
      tailHeldOnce = false;
      const boundary = Math.max(pending.lastIndexOf("\n"), pending.lastIndexOf("\r"));
      if (boundary >= 0) {
        emit(redactSecrets(pending.slice(0, boundary + 1)));
        pending = pending.slice(boundary + 1);
      }
      clearTimer();
      if (pending) {
        timer = setTimeout(onQuietTimer, STREAM_FLUSH_QUIET_MS);
        timer.unref?.();
      }
    },
    flush: emitPending
  };
}
