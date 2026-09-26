/*
 * A small REST API as a simpler alternative to the GraphQL endpoint.
 *
 * Scope is deliberately narrow: authenticate with an API key and create /
 * list CTFs and tasks (with tags, which act as categories). Every request is
 * forwarded to the internal GraphQL endpoint carrying the same `X-API-Key`
 * header, so all permission checks, HedgeDoc pad creation and live-update
 * notifications behave exactly as they do for a GraphQL client -- this layer
 * only translates REST <-> GraphQL, it never touches the database directly.
 *
 * Auth: send `X-API-Key: <token>` (see docs/API_KEYS.md). The key's owner and
 * role determine what the request may do.
 */
import { Router, json, Request, Response } from "express";
import axios from "axios";
import config from "../config";

const GRAPHQL_URL = `http://127.0.0.1:${config.web.port}/graphql`;

type GqlResult<T = Record<string, unknown>> = {
  data?: T;
  errors?: { message: string }[];
};

async function callGraphql<T = Record<string, unknown>>(
  apiKey: string,
  query: string,
  variables: Record<string, unknown>
): Promise<GqlResult<T>> {
  const res = await axios.post<GqlResult<T>>(
    GRAPHQL_URL,
    { query, variables },
    {
      headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
      validateStatus: () => true,
    }
  );
  return res.data;
}

// Accept tags under several friendly names: tags/categories (arrays) or
// tag/category (single string). Trim and drop empties; the DB lowercases them.
function normalizeTags(body: Record<string, unknown>): string[] {
  const raw: unknown[] = [];
  for (const key of ["tags", "categories"]) {
    const v = body[key];
    if (Array.isArray(v)) raw.push(...v);
  }
  for (const key of ["tag", "category"]) {
    const v = body[key];
    if (typeof v === "string") raw.push(v);
  }
  return raw
    .filter((t): t is string => typeof t === "string")
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
}

type ApiKeyRequest = Request & { apiKey: string };

export function restRoutes(): Router {
  const router = Router();
  router.use(json());

  // Every REST route requires an API key.
  router.use((req: Request, res: Response, next) => {
    const key = req.header("x-api-key");
    if (!key) {
      res.status(401).json({ error: "Missing X-API-Key header" });
      return;
    }
    (req as ApiKeyRequest).apiKey = key;
    next();
  });

  const keyOf = (req: Request) => (req as ApiKeyRequest).apiKey;

  // GET /api/ctfs -> list CTFs (id + basic info)
  router.get("/ctfs", async (req, res) => {
    const r = await callGraphql<{ ctfs: { nodes: unknown[] } }>(
      keyOf(req),
      `{ ctfs { nodes { id title startTime endTime } } }`,
      {}
    );
    if (r.errors) {
      res.status(403).json({ error: r.errors[0].message });
      return;
    }
    res.json(r.data?.ctfs.nodes ?? []);
  });

  // POST /api/ctfs -> create a CTF. Body: { title, startTime, endTime, weight?, description?, ctfUrl?, ctftimeUrl? }
  router.post("/ctfs", async (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const { title, startTime, endTime } = body;
    if (typeof title !== "string" || title.trim() === "") {
      res.status(400).json({ error: "title is required" });
      return;
    }
    if (typeof startTime !== "string" || typeof endTime !== "string") {
      res
        .status(400)
        .json({ error: "startTime and endTime are required (ISO 8601)" });
      return;
    }
    const ctf: Record<string, unknown> = { title, startTime, endTime };
    for (const key of ["weight", "description", "ctfUrl", "ctftimeUrl", "logoUrl"]) {
      if (body[key] !== undefined) ctf[key] = body[key];
    }
    const r = await callGraphql<{ createCtf: { ctf: { id: number } | null } }>(
      keyOf(req),
      `mutation($input:CreateCtfInput!){ createCtf(input:$input){ ctf { id title startTime endTime } } }`,
      { input: { ctf } }
    );
    if (r.errors) {
      res.status(400).json({ error: r.errors[0].message });
      return;
    }
    const created = r.data?.createCtf?.ctf;
    if (!created) {
      res.status(403).json({ error: "Not allowed to create a CTF" });
      return;
    }
    res.status(201).json(created);
  });

  // GET /api/ctfs/:ctfId/tasks -> list tasks in a CTF (with their tags)
  router.get("/ctfs/:ctfId/tasks", async (req, res) => {
    const ctfId = Number(req.params.ctfId);
    if (!Number.isInteger(ctfId)) {
      res.status(400).json({ error: "ctfId must be an integer" });
      return;
    }
    const r = await callGraphql<{
      ctfs: {
        nodes: {
          tasks: {
            nodes: {
              id: number;
              title: string;
              flag: string;
              description: string;
              assignedTags: { nodes: { tag: { tag: string } | null }[] };
            }[];
          };
        }[];
      };
    }>(
      keyOf(req),
      `query($id:Int!){
         ctfs(first:1, condition:{id:$id}){
           nodes{
             tasks{ nodes{ id title flag description
               assignedTags{ nodes{ tag{ tag } } } } }
           }
         }
       }`,
      { id: ctfId }
    );
    if (r.errors) {
      res.status(403).json({ error: r.errors[0].message });
      return;
    }
    const ctf = r.data?.ctfs.nodes[0];
    if (!ctf) {
      res.status(404).json({ error: "CTF not found" });
      return;
    }
    res.json(
      ctf.tasks.nodes.map((t) => ({
        id: t.id,
        title: t.title,
        flag: t.flag,
        description: t.description,
        tags: t.assignedTags.nodes
          .map((a) => a.tag?.tag)
          .filter((x): x is string => typeof x === "string"),
      }))
    );
  });

  // POST /api/ctfs/:ctfId/tasks -> create a task.
  // Body: { title (required), description?, flag?, tags?/categories?/tag?/category? }
  router.post("/ctfs/:ctfId/tasks", async (req, res) => {
    const ctfId = Number(req.params.ctfId);
    if (!Number.isInteger(ctfId)) {
      res.status(400).json({ error: "ctfId must be an integer" });
      return;
    }
    const body = (req.body ?? {}) as Record<string, unknown>;
    const title = body.title;
    if (typeof title !== "string" || title.trim() === "") {
      res.status(400).json({ error: "title is required" });
      return;
    }
    const description =
      typeof body.description === "string" ? body.description : null;
    const flag = typeof body.flag === "string" ? body.flag : null;
    const tags = normalizeTags(body);

    const created = await callGraphql<{
      createTask: { task: { id: number; title: string } | null } | null;
    }>(
      keyOf(req),
      `mutation($input:CreateTaskInput!){ createTask(input:$input){ task { id title } } }`,
      { input: { ctfId, title, description, flag, tags } }
    );
    if (created.errors) {
      res.status(400).json({ error: created.errors[0].message });
      return;
    }
    const task = created.data?.createTask?.task;
    if (!task) {
      res.status(403).json({
        error:
          "Not allowed to create tasks in this CTF (check the API key's role and CTF access)",
      });
      return;
    }

    // createTask only writes tags into the pad heading; assign them for real.
    if (tags.length > 0) {
      const tagged = await callGraphql(
        keyOf(req),
        `mutation($input:AddTagsForTaskInput!){ addTagsForTask(input:$input){ clientMutationId } }`,
        { input: { taskId: task.id, tags } }
      );
      if (tagged.errors) {
        res.status(207).json({
          id: task.id,
          title: task.title,
          warning: `Task created but tagging failed: ${tagged.errors[0].message}`,
        });
        return;
      }
    }

    res.status(201).json({ id: task.id, title: task.title, tags });
  });

  return router;
}
