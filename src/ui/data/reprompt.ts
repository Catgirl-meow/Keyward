// Master-password re-prompt state for this page (popup or vault tab). The item view and the
// popup's Fill share it: one confirmation covers both for a few minutes.
const GRACE_MS = 5 * 60_000;
let verifiedAt = 0;

export const markVerified = () => void (verifiedAt = Date.now());
export const recentlyVerified = () => Date.now() - verifiedAt <= GRACE_MS;
