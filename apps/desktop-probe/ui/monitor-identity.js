(function (root) {
  "use strict";

  function monitorIdentityChanged(previousIdentity, currentIdentity) {
    return previousIdentity !== null
      && previousIdentity !== undefined
      && currentIdentity !== null
      && currentIdentity !== undefined
      && previousIdentity !== currentIdentity;
  }

  if (typeof module === "object" && module.exports) {
    module.exports = { monitorIdentityChanged };
  } else {
    root.monitorIdentityChanged = monitorIdentityChanged;
  }
})(globalThis);
