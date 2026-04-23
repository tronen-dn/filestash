// Stub for the upstream cross-window move feature. The real implementation
// was referenced in commit 6e6af734 but the source file was never added to
// the repo, which breaks ctrl_filespage.js's dynamic import and prevents the
// file browser from loading. This noop lets the page render; cross-window
// move will simply not do anything until upstream ships the real module.
export default function componentMove() {}
