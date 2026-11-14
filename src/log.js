// Structured JSON logging: one line per event on stdout.

const REDACTED_KEYS = new Set(['authorization', 'token', 'password']);

function replacer(key, value) {
  if (REDACTED_KEYS.has(key.toLowerCase())) return '[redacted]';
  // Error objects serialize to {} by default; expand them explicitly.
  if (value instanceof Error) {
    return {
      name: value.name,
      message: value.message,
      ...(value.code !== undefined && { code: value.code }),
      stack: value.stack,
      ...(value.cause !== undefined && { cause: value.cause }),
    };
  }
  return value;
}

// If whatever reads our stdout goes away, keep serving rather than crash on the next log line.
process.stdout.on('error', (err) => {
  if (err.code !== 'EPIPE') throw err;
});

function write(level, msg, fields) {
  const line = JSON.stringify({ ts: new Date().toISOString(), level, msg, ...fields }, replacer);
  process.stdout.write(line + '\n');
}

export const log = {
  info: (msg, fields = {}) => write('info', msg, fields),
  warn: (msg, fields = {}) => write('warn', msg, fields),
  error: (msg, fields = {}) => write('error', msg, fields),
};
