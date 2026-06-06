import cors from "cors";
import express from "express";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

type StoredNote = {
  payload: string | null;
  updatedAt: string | null;
};

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const defaultDataFile = path.resolve(__dirname, "../data/note.json");
const dataFile = process.env.DATA_FILE
  ? path.resolve(process.env.DATA_FILE)
  : defaultDataFile;
const port = Number(process.env.PORT ?? 1873);

const app = express();

app.use(cors());
app.use(express.json({ limit: "1mb" }));

async function readNote(): Promise<StoredNote> {
  try {
    const raw = await readFile(dataFile, "utf8");
    const parsed = JSON.parse(raw) as StoredNote;

    return {
      payload: typeof parsed.payload === "string" ? parsed.payload : null,
      updatedAt: typeof parsed.updatedAt === "string" ? parsed.updatedAt : null
    };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      return { payload: null, updatedAt: null };
    }

    throw error;
  }
}

async function writeNote(payload: string): Promise<StoredNote> {
  const nextNote = {
    payload,
    updatedAt: new Date().toISOString()
  };
  const tempFile = `${dataFile}.${process.pid}.tmp`;

  await mkdir(path.dirname(dataFile), { recursive: true });
  await writeFile(tempFile, JSON.stringify(nextNote, null, 2), "utf8");
  await rename(tempFile, dataFile);

  return nextNote;
}

app.get("/api/health", (_request, response) => {
  response.json({ ok: true });
});

app.get("/api/note", async (_request, response, next) => {
  try {
    response.json(await readNote());
  } catch (error) {
    next(error);
  }
});

app.put("/api/note", async (request, response, next) => {
  try {
    const payload = request.body?.payload;

    if (typeof payload !== "string" || payload.length > 750_000) {
      response.status(400).json({ error: "payload must be a string under 750KB" });
      return;
    }

    response.json(await writeNote(payload));
  } catch (error) {
    next(error);
  }
});

app.use(
  (
    error: unknown,
    _request: express.Request,
    response: express.Response,
    _next: express.NextFunction
  ) => {
    console.error(error);
    response.status(500).json({ error: "internal server error" });
  }
);

app.listen(port, "0.0.0.0", () => {
  console.log(`cloud-notes backend listening on ${port}`);
});
