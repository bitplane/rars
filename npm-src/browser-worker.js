import init, * as wasm from "./wasm/rars_wasm.js";
import { startWorker } from "./worker-engine.js";

await init();

startWorker({
  onMessage(callback) { self.addEventListener("message", (event) => callback(event.data)); },
  post(message, transfers = []) { self.postMessage(message, transfers); },
}, wasm, {
  readFile() { throw new Error("filesystem input is only available in Node"); },
  writeAtomic() { throw new Error("filesystem output is only available in Node"); },
  writeVolumes() { throw new Error("filesystem output is only available in Node"); },
});
