const now = new Date();
const past = new Date(now.getTime() - 12000 * 60 * 1000);

return [{
  now: now.toISOString(),
  past: past.toISOString()
}];
