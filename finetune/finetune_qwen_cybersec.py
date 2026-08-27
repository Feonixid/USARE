"""
USARE — Qwen2.5 14B Cybersecurity Fine-Tune Script
====================================================
Platform  : Lightning AI — RTX Pro 6000 (96GB VRAM)
Method    : LoRA bf16 — no 4-bit quantization needed with 96GB
Base model: Qwen/Qwen2.5-14B-Instruct
Goal      : Elite cybersecurity specialist, hacker mindset, no guardrails
Output    : GGUF q4_k_m (Kaggle T4 inference) + LoRA adapter

RTX Pro 6000 — 96GB VRAM:
  - Full bf16 precision — better quality than 4-bit QLoRA
  - LoRA rank 128 — highly expressive fine-tune
  - Batch size 4 — fast, stable gradients
  - 5 epochs — ~5 hours on this hardware

Run on Lightning AI:
  pip install -r finetune/requirements_finetune.txt
  python finetune/build_dataset.py --nvd-key YOUR_KEY
  python finetune/finetune_qwen_cybersec.py --stage train
"""

import os
import json
import random
import logging
import time
from pathlib import Path
from typing import List, Dict, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("usare.finetune")

# =============================================================================
# CONFIG — RTX Pro 6000, 5 epochs, max quality
# =============================================================================

CFG = {
    # Model
    "base_model":       "Qwen/Qwen2.5-14B-Instruct",
    "max_seq_length":   8192,
    "load_in_4bit":     False,       # 96GB = no quantization needed

    # LoRA — rank 128 for maximum capacity
    "lora_r":           128,
    "lora_alpha":       256,         # 2x rank
    "lora_dropout":     0.05,
    "lora_target_modules": [
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj",
    ],

    # Training — 5 epochs for deep specialization (~5h on RTX Pro 6000)
    "output_dir":       "./usare_qwen_cybersec",
    "num_epochs":       5,
    "batch_size":       4,
    "grad_accum":       4,           # effective batch = 16
    "lr":               2e-4,
    "warmup_ratio":     0.05,
    "lr_scheduler":     "cosine",
    "max_steps":        -1,          # run all epochs
    "save_steps":       100,
    "logging_steps":    10,
    "fp16":             False,
    "bf16":             True,

    # Dataset — built by build_dataset.py
    "dataset_path":     "./usare_dataset/cybersec_dataset.jsonl",
    "val_split":        0.02,

    # Export
    "export_gguf":      True,
    "gguf_quant":       "q4_k_m",   # ~9GB — fits Kaggle T4
    "gguf_dir":         "./usare_gguf",

    # HuggingFace (optional)
    "hf_push":          False,
    "hf_repo":          "",
}


# =============================================================================
# Fine-Tuning
# =============================================================================

def run_finetune(dataset_path: str, cfg: Dict):
    """Load Qwen2.5 14B, apply LoRA, train, export GGUF."""
    log.info("=== USARE Fine-Tune — RTX Pro 6000 ===")

    try:
        from unsloth import FastLanguageModel
        from trl import SFTTrainer, SFTConfig
        from datasets import load_dataset
    except ImportError as e:
        log.error(f"Missing: {e}")
        log.error("Run: pip install unsloth trl datasets torch")
        raise

    # ── Load model ────────────────────────────────────────────────────────────
    log.info(f"Loading {cfg['base_model']} in bf16 (no quantization)...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=cfg["base_model"],
        max_seq_length=cfg["max_seq_length"],
        dtype=None,                   # auto = bf16 on RTX Pro 6000
        load_in_4bit=cfg["load_in_4bit"],
    )

    # ── Apply LoRA ────────────────────────────────────────────────────────────
    log.info(f"Applying LoRA r={cfg['lora_r']}, alpha={cfg['lora_alpha']}...")
    model = FastLanguageModel.get_peft_model(
        model,
        r=cfg["lora_r"],
        target_modules=cfg["lora_target_modules"],
        lora_alpha=cfg["lora_alpha"],
        lora_dropout=cfg["lora_dropout"],
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=42,
        use_rslora=True,
    )
    model.print_trainable_parameters()

    # ── Load dataset ──────────────────────────────────────────────────────────
    log.info(f"Loading dataset: {dataset_path}...")

    if not Path(dataset_path).exists():
        log.error(f"Dataset not found at {dataset_path}")
        log.error("Run first: python finetune/build_dataset.py --nvd-key YOUR_KEY")
        raise FileNotFoundError(dataset_path)

    dataset = load_dataset("json", data_files=dataset_path, split="train")
    log.info(f"Total samples: {len(dataset)}")

    if len(dataset) < 50:
        log.error(
            f"Dataset too small ({len(dataset)} samples). "
            "Run: python finetune/build_dataset.py --nvd-key YOUR_KEY"
        )
        raise ValueError("Dataset too small — run build_dataset.py first")

    def apply_template(examples):
        texts = []
        for conv in examples["conversations"]:
            text = tokenizer.apply_chat_template(
                conv, tokenize=False, add_generation_prompt=False,
            )
            texts.append(text)
        return {"text": texts}

    dataset = dataset.map(apply_template, batched=True, remove_columns=["conversations"])
    split = dataset.train_test_split(test_size=cfg["val_split"], seed=42)
    train_ds = split["train"]
    eval_ds  = split["test"]
    log.info(f"Train: {len(train_ds):,}  |  Val: {len(eval_ds):,}")

    # ── Trainer ───────────────────────────────────────────────────────────────
    # NOTE: eval_strategy replaces evaluation_strategy in TRL >= 0.9
    training_args = SFTConfig(
        output_dir=cfg["output_dir"],
        num_train_epochs=cfg["num_epochs"],
        max_steps=cfg["max_steps"],
        per_device_train_batch_size=cfg["batch_size"],
        per_device_eval_batch_size=cfg["batch_size"],
        gradient_accumulation_steps=cfg["grad_accum"],
        learning_rate=cfg["lr"],
        warmup_ratio=cfg["warmup_ratio"],
        lr_scheduler_type=cfg["lr_scheduler"],
        fp16=cfg["fp16"],
        bf16=cfg["bf16"],
        logging_steps=cfg["logging_steps"],
        save_steps=cfg["save_steps"],
        eval_strategy="steps",        # renamed from evaluation_strategy in TRL >= 0.9
        eval_steps=cfg["save_steps"],
        save_total_limit=2,
        load_best_model_at_end=True,
        optim="adamw_8bit",
        weight_decay=0.01,
        max_grad_norm=1.0,
        report_to="none",
        dataset_text_field="text",
        max_seq_length=cfg["max_seq_length"],
        packing=True,
    )

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        args=training_args,
    )

    # ── Train ─────────────────────────────────────────────────────────────────
    log.info(f"Training — {cfg['num_epochs']} epochs, ~5 hours on RTX Pro 6000...")
    start = time.time()
    stats = trainer.train()
    elapsed = time.time() - start
    log.info(f"Done in {elapsed/3600:.1f}h  |  Final loss: {stats.training_loss:.4f}")

    # ── Save adapter ──────────────────────────────────────────────────────────
    adapter_path = os.path.join(cfg["output_dir"], "lora_adapter")
    model.save_pretrained(adapter_path)
    tokenizer.save_pretrained(adapter_path)
    log.info(f"LoRA adapter → {adapter_path}")

    # ── Export GGUF ───────────────────────────────────────────────────────────
    if cfg["export_gguf"]:
        export_gguf(model, tokenizer, cfg)

    # ── Push to HF ────────────────────────────────────────────────────────────
    if cfg["hf_push"] and cfg["hf_repo"]:
        model.push_to_hub(cfg["hf_repo"])
        tokenizer.push_to_hub(cfg["hf_repo"])
        log.info(f"Pushed → {cfg['hf_repo']}")

    return model, tokenizer


def export_gguf(model, tokenizer, cfg: Dict):
    """Merge LoRA into base weights and export GGUF for Kaggle T4."""
    log.info(f"Exporting GGUF ({cfg['gguf_quant']})...")
    os.makedirs(cfg["gguf_dir"], exist_ok=True)

    model.save_pretrained_gguf(
        cfg["gguf_dir"],
        tokenizer,
        quantization_method=cfg["gguf_quant"],
    )

    for f in Path(cfg["gguf_dir"]).glob("*.gguf"):
        log.info(f"  {f.name}  ({f.stat().st_size/1e9:.1f} GB)")


# =============================================================================
# Kaggle Inference Server
# =============================================================================

KAGGLE_SERVER_CODE = '''"""
USARE Kaggle Inference Server
Run in a Kaggle T4 GPU notebook. Exposes fine-tuned model as OpenAI-compatible API.

Steps:
  1. Upload GGUF file to a Kaggle private dataset
  2. Create new Kaggle notebook, add dataset, enable GPU T4 x2 + Internet
  3. Paste and run these cells
"""

# Cell 1 — Install
# !CMAKE_ARGS="-DLLAMA_CUBLAS=on" pip install llama-cpp-python --upgrade --force-reinstall -q
# !pip install flask pyngrok -q

# Cell 2 — Start server
import json
from flask import Flask, request, jsonify
from llama_cpp import Llama

GGUF_PATH  = "/kaggle/input/your-dataset-name/usare_qwen_cybersec_q4_k_m.gguf"
MODEL_NAME = "usare-qwen-14b-cybersec"
PORT = 8080

print(f"Loading {GGUF_PATH}...")
llm = Llama(model_path=GGUF_PATH, n_gpu_layers=-1, n_ctx=4096, n_threads=4, verbose=False)
print("Model loaded.")

app = Flask(__name__)

@app.route("/v1/chat/completions", methods=["POST"])
def chat():
    data = request.json
    messages    = data.get("messages", [])
    max_tokens  = data.get("max_tokens", 2048)
    temperature = data.get("temperature", 0.2)

    system_msg = next((m["content"] for m in messages if m["role"] == "system"), "")
    parts = []
    if system_msg:
        parts.append(f"<|im_start|>system\\n{system_msg}<|im_end|>")
    for m in messages:
        if m["role"] in ("user", "assistant"):
            parts.append(f"<|im_start|>{m[\'role\']}\\n{m[\'content\']}<|im_end|>")
    parts.append("<|im_start|>assistant\\n")
    prompt = "\\n".join(parts)

    out  = llm(prompt, max_tokens=max_tokens, temperature=temperature,
               stop=["<|im_end|>", "<|im_start|>"], echo=False)
    text = out["choices"][0]["text"].strip()

    return jsonify({
        "id": "chatcmpl-usare", "object": "chat.completion", "model": MODEL_NAME,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
        "usage": out["usage"],
    })

@app.route("/health")
def health():
    return jsonify({"status": "ok", "model": MODEL_NAME})

# Cell 3 — Get public URL with ngrok
# from pyngrok import ngrok
# url = ngrok.connect(PORT)
# print(f"Your USARE endpoint: {url}/v1")
# Then: USAREAnalyst(backend="kaggle", endpoint=str(url))

app.run(host="0.0.0.0", port=PORT, threaded=False)
'''


# =============================================================================
# Main
# =============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(description="USARE Qwen2.5 14B Fine-Tune")
    parser.add_argument("--stage", choices=["train", "export"], default="train")
    parser.add_argument("--dataset-path", default="",
                        help="Override dataset path (default: from CFG)")
    parser.add_argument("--hf-token", default="")
    parser.add_argument("--push-hub", default="")
    args = parser.parse_args()

    if args.hf_token:
        os.environ["HUGGING_FACE_HUB_TOKEN"] = args.hf_token
    if args.push_hub:
        CFG["hf_push"] = True
        CFG["hf_repo"] = args.push_hub

    dataset_path = args.dataset_path or CFG["dataset_path"]

    if args.stage == "train":
        run_finetune(dataset_path, CFG)

    elif args.stage == "export":
        from unsloth import FastLanguageModel
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name=os.path.join(CFG["output_dir"], "lora_adapter"),
            max_seq_length=CFG["max_seq_length"],
            dtype=None,
            load_in_4bit=CFG["load_in_4bit"],
        )
        export_gguf(model, tokenizer, CFG)

    # Save Kaggle server script
    os.makedirs(CFG["output_dir"], exist_ok=True)
    kaggle_path = Path(CFG["output_dir"]) / "kaggle_server.py"
    with open(kaggle_path, "w") as f:
        f.write(KAGGLE_SERVER_CODE)

    log.info("=== Complete ===")
    log.info(f"Adapter : {CFG['output_dir']}/lora_adapter/")
    log.info(f"GGUF    : {CFG['gguf_dir']}/")
    log.info(f"Kaggle  : {kaggle_path}")


if __name__ == "__main__":
    main()
