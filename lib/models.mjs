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
  return ["text"];
}

export function toMagpieModel(model, base) {
  const mods = modalities(model);
  return {
    id: model.id,
    name: model.name || model.display_name || base?.name || model.id,
    limit: {
      context: model.limit?.context || model.context_length || base?.limit?.context || 131072,
      output: model.limit?.output || base?.limit?.output || 32768,
    },
    tool_call: model.tool_call !== false,
    attachment: base?.attachment || mods.some((m) => m !== "text"),
  };
}

export function toConfigModels(models) {
  return Object.fromEntries(models.map((m) => [m.id, toMagpieModel(m)]));
}

export function mergeModels(base, upstream) {
  const out = {};
  for (const model of upstream || []) {
    const id = model.id || model.model;
    if (!id) continue;
    out[id] = { ...(base[id] || {}), ...toMagpieModel({ ...model, id }, base[id]) };
  }
  return Object.keys(out).length ? out : base;
}
