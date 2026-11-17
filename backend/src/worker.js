import { DurableObject } from "cloudflare:workers";
import { httpServerHandler } from "cloudflare:node";
import app, { runWithCloudflareEnvironment } from "./server.js";

app.listen(3000);
const backend = httpServerHandler({ port: 3000 });

export class ApiCoordinator extends DurableObject {
  #tail = Promise.resolve();

  async fetch(request) {
    let release;
    const previous = this.#tail;
    this.#tail = new Promise((resolve) => { release = resolve; });
    await previous;
    try {
      return await runWithCloudflareEnvironment(this.env, () => backend.fetch(request, this.env, this.ctx));
    } finally {
      release();
    }
  }
}

export default {
  async fetch(request, env) {
    const id = env.API_COORDINATOR.idFromName("cb-secure-global-api");
    return env.API_COORDINATOR.get(id).fetch(request);
  },
};
