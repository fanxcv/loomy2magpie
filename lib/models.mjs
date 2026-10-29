// 上游 /models 失败时的兜底目录，取自 loomy2api constants.py。
export const FALLBACK_MODELS = [
  { id: "spark-x", name: "Spark X2.5 (x0.1)", context_length: 1048576, modalities: ["text"] },
  { id: "GLM-5.3-Flash", name: "GLM 5.3 Flash (x0.8)", context_length: 1048576, modalities: ["text", "image", "video"] },
  { id: "qwen3.8-flash", name: "qwen 3.8 flash (x0.8)", context_length: 1000000, modalities: ["text", "image", "video"] },
  { id: "deepseek-v4-flash-0731", name: "DeepSeek V4 Flash 0731 (x3.0)", context_length: 1048576, modalities: ["text"] },
  { id: "mimo-v2.5", name: "MiMo V2.5 (x3.3)", context_length: 1048576, modalities: ["text", "image", "audio", "video"] },
  { id: "MiniMax-M3", name: "MiniMax M3 (x4.0)", context_length: 1048576, modalities: ["text", "image", "video"] },
  { id: "Kimi-k2.6", name: "Kimi k2.6 (x6.5)", context_length: 262144, modalities: ["text", "image", "video"] },
  { id: "qwen-3.8-max", name: "Qwen 3.8 Max (x12.0)", context_length: 1000000, modalities: ["text"] },
  { id: "Hy-Image-3.5-preview", name: "Hy image 3.5 preview", context_length: 100000, modalities: ["text", "image"] },
  { id: "doubao-seedream-5-lite", name: "Doubao seedream 5 lite", context_length: 128000, modalities: ["text", "image"] },
  { id: "qwen-image-3.0-pro", name: "qwen image 3.0 pro", context_length: 131072, modalities: ["text", "image"] },
];

function modalities(model) {
  const raw = model.modalities;
  if (Array.isArray(raw)) return raw;
  if (Array.isArray(raw?.input)) return raw.input;
  return null;
}

const INPUT_KINDS = ["text", "image", "audio", "video", "pdf"];

const inputCapabilities = (mods) =>
  Object.fromEntries(INPUT_KINDS.map((kind) => [kind, kind === "text" || mods.includes(kind)]));

// 上游没给 modalities 时沿用 base 里已知的输入能力。
function baseModalities(base) {
  const input = base?.capabilities?.input;
  if (!input || typeof input !== "object") return null;
  return INPUT_KINDS.filter((kind) => input[kind] === true);
}

const RATE_SUFFIX = /\(\s*[x×]\s*([\d.]+)\s*\)\s*$/;

// 上游把积分倍率写在模型名末尾（"Spark X2.5 (x0.1)"）；0 表示免费。
function takeRate(value) {
  const name = String(value ?? "");
  const match = RATE_SUFFIX.exec(name);
  if (!match) return { name };
  const rate = Number(match[1]);
  if (!Number.isFinite(rate)) return { name };
  const stripped = name.slice(0, match.index).trim();
  return rate === 0 ? { name: stripped, free: true } : { name: stripped, rate };
}

function limitOf(model, base) {
  return {
    ...(base?.limit || {}),
    context: model.limit?.context || model.context_length || base?.limit?.context || 131072,
    output: model.limit?.output || model.max_output_tokens || base?.limit?.output || 32768,
  };
}

function reasoningOf(model, base) {
  return model.reasoning ?? model.capabilities?.reasoning ?? base?.capabilities?.reasoning ?? false;
}

// config 钩子给 OpenCode 的 provider.models 形状。
export function toConfigModel(model) {
  const mods = modalities(model) || ["text"];
  return {
    id: model.id,
    name: model.name || model.display_name || model.id,
    limit: limitOf(model),
    reasoning: reasoningOf(model),
    tool_call: model.tool_call !== false,
    attachment: model.attachment ?? mods.some((kind) => kind !== "text"),
    modalities: { input: mods, output: ["text"] },
  };
}

export function toConfigModels(models) {
  return Object.fromEntries(models.map((m) => [m.id, toConfigModel(m)]));
}

// provider.models 钩子整体替换宿主模型表，必须是宿主的 GUI 形状。
export function toHookModel(model, base = {}) {
  const mods = modalities(model) ?? baseModalities(base) ?? ["text"];
  const picked = takeRate(model.name || model.display_name || base.name || model.id);
  const out = {
    ...base,
    id: model.id,
    name: picked.name || model.id,
    limit: limitOf(model, base),
    capabilities: {
      ...(base.capabilities || {}),
      toolcall: model.tool_call !== false,
      reasoning: reasoningOf(model, base),
      attachment: model.attachment ?? mods.some((kind) => kind !== "text"),
      input: inputCapabilities(mods),
      output: { text: true },
    },
  };
  if (picked.free) {
    delete out.rate;
    out.free = true;
  } else if (picked.rate !== undefined) {
    delete out.free;
    out.rate = picked.rate;
  }
  return out;
}

export function mergeModels(base, upstream) {
  const out = {};
  for (const model of upstream || []) {
    const id = model.id || model.model;
    if (!id) continue;
    out[id] = toHookModel({ ...model, id }, base[id] || {});
  }
  return Object.keys(out).length ? out : base;
}
