const test = require("node:test");
const assert = require("node:assert/strict");
const { monitorIdentityChanged } = require("../monitor-identity.js");

test("ordinary window movement on one monitor does not increment monitor changes", () => {
  assert.equal(monitorIdentityChanged("display-a|0|0", "display-a|0|0"), false);
});

test("initially discovering a monitor is not a move between monitors", () => {
  assert.equal(monitorIdentityChanged(null, "display-a|0|0"), false);
});

test("crossing to a different monitor identity increments exactly once", () => {
  assert.equal(monitorIdentityChanged("display-a|0|0", "display-b|1920|0"), true);
  assert.equal(monitorIdentityChanged("display-b|1920|0", "display-b|1920|0"), false);
});

test("an unavailable monitor identity is not counted as a transition", () => {
  assert.equal(monitorIdentityChanged("display-a|0|0", null), false);
  assert.equal(monitorIdentityChanged(null, null), false);
});
