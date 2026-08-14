var __defProp = Object.defineProperty;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);

// src/protocol.ts
function parseControl(data) {
  let m;
  try {
    m = JSON.parse(data);
  } catch {
    return null;
  }
  if (!m || typeof m.type !== "string") {
    return null;
  }
  if (m.type === "error") {
    return { type: "error", message: typeof m.message === "string" ? m.message : void 0 };
  }
  if (m.type === "exit") {
    return { type: "exit" };
  }
  if (m.type === "hostkey") {
    if (typeof m.host !== "string" || typeof m.key_type !== "string" || typeof m.fingerprint !== "string" || typeof m.known !== "boolean") {
      return null;
    }
    const mode = m.mode === "confirm" || m.mode === "notify" ? m.mode : "confirm";
    return {
      type: "hostkey",
      host: m.host,
      key_type: m.key_type,
      fingerprint: m.fingerprint,
      known: m.known,
      mode
    };
  }
  return null;
}
function encodeResize(rows, cols) {
  return JSON.stringify({ type: "resize", rows, cols });
}
function encodeHostKeyResponse(accept) {
  return JSON.stringify({ type: "hostkey-response", accept });
}

export {
  __publicField,
  parseControl,
  encodeResize,
  encodeHostKeyResponse
};
//# sourceMappingURL=chunk-JUMKVBAM.js.map