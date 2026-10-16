// Watchtower's password scoring, off the page's thread: zxcvbn needs up to 40 ms a password, so
// 200 passwords on the page froze it for seconds. The page posts [password, inputs] pairs and
// gets the scores back in the same order. The dictionaries load on the first request.
import { ZxcvbnFactory } from "@zxcvbn-ts/core";
import { unFrontCode } from "../core/watchtower/frontcode.ts";

export interface ScoreRequest {
  id: number;
  pairs: [password: string, inputs: string[]][];
}
export type ScoreReply = { id: number; scores: number[] } | { id: number; error: string };

let factory: Promise<ZxcvbnFactory> | null = null;

async function load(): Promise<ZxcvbnFactory> {
  const res = await fetch("/data/zxcvbn.json.gz");
  if (!res.ok || !res.body) throw new Error("Password dictionaries are missing");
  const data = await new Response(res.body.pipeThrough(new DecompressionStream("gzip"))).json();
  const dictionary = Object.fromEntries(Object.entries(data.lists as Record<string, string>).map(([k, v]) => [k, unFrontCode(v)]));
  return new ZxcvbnFactory({ graphs: data.graphs, dictionary });
}

self.onmessage = async (e: MessageEvent<ScoreRequest>) => {
  const { id, pairs } = e.data;
  try {
    const z = await (factory ??= load().catch((err) => {
      factory = null;
      throw err;
    }));
    // A very long password is strong or a repeat zxcvbn sees in its first 100 characters; past
    // that its matching only gets slower.
    self.postMessage({ id, scores: pairs.map(([pw, inputs]) => z.check(pw.slice(0, 100), inputs).score) } satisfies ScoreReply);
  } catch (err) {
    self.postMessage({ id, error: (err as Error).message } satisfies ScoreReply);
  }
};
