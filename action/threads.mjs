// Our own review threads whose finding is gone (fixed, or the code was removed). The action
// resolves them, so a pull request does not keep conversations open for problems that no
// longer exist. Threads from people, and threads already resolved, are left alone.
export function staleThreads(threads, fingerprints) {
  return threads.filter(t => !t.isResolved).filter(t => {
    const m = /<!-- vetcode:([\w-]+) -->/.exec(t.comments?.nodes?.[0]?.body || "");
    return m && !fingerprints.has(m[1]);
  }).map(t => t.id);
}
