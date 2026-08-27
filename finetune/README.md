# USARE Fine-Tuning — Lightning AI Quick Start

## What this does
Fine-tunes **Qwen2.5 14B Instruct** on cybersecurity data using QLoRA,
then exports a GGUF file you can serve from Kaggle for inference.

---

## Step 1 — Set up Lightning AI

1. Go to [lightning.ai](https://lightning.ai) and create a Studio
2. Choose **A10G** GPU (24GB VRAM) — fits 14B at 4-bit comfortably
3. Clone or upload the USARE project files

---

## Step 2 — Install dependencies

```bash
pip install -r finetune/requirements_finetune.txt
```

> Unsloth installs PyTorch automatically. If you get a CUDA version mismatch,
> check [unsloth's install guide](https://github.com/unslothai/unsloth) for your CUDA version.

---

## Step 3 — Build dataset only (fast, no GPU needed)

```bash
python finetune/finetune_qwen_cybersec.py --stage dataset
```

Optionally add real CVE data from NVD (free, no key needed but slow without one):
```bash
python finetune/finetune_qwen_cybersec.py --stage dataset --nvd-key YOUR_NVD_KEY
```

Get a free NVD API key at: https://nvd.nist.gov/developers/request-an-api-key

---

## Step 4 — Run full pipeline (dataset + train + export GGUF)

```bash
python finetune/finetune_qwen_cybersec.py --stage all
```

Or train on an existing dataset:
```bash
python finetune/finetune_qwen_cybersec.py --stage train --dataset-path ./usare_dataset/cybersec_dataset.jsonl
```

**Estimated training time on A10G:** ~3-5 hours for 3 epochs

---

## Step 5 — What you get after training

```
usare_qwen_cybersec/
  lora_adapter/         ← LoRA weights only (small, ~300MB)
  kaggle_server.py      ← Ready-to-run Kaggle inference server

usare_gguf/
  usare_qwen_cybersec_q4_k_m.gguf  ← ~8-9GB, runs on Kaggle T4
```

---

## Step 6 — Deploy on Kaggle

1. Upload `usare_qwen_cybersec_q4_k_m.gguf` to a **Kaggle private dataset**
2. Create a new Kaggle notebook:
   - GPU: T4 x2
   - Enable Internet access
3. Add your dataset to the notebook
4. Copy the contents of `kaggle_server.py` into cells
5. Update `GGUF_PATH` to match your dataset path
6. Run — the server starts on port 8080
7. Use ngrok to get a public URL:
   ```python
   from pyngrok import ngrok
   url = ngrok.connect(8080)
   print(url)  # e.g. https://abc123.ngrok.io
   ```

---

## Step 7 — Connect USARE to your model

```python
from ops.ai_analyst import USAREAnalyst

analyst = USAREAnalyst(
    backend="kaggle",
    endpoint="https://abc123.ngrok.io",   # your ngrok URL
    model="usare-qwen-14b-cybersec",
)

# Analyze a scan
report = analyst.analyze_scan(scan_data)
analyst.print_report(report)
```

---

## Dataset expansion (optional)

To add more training data beyond what's built-in, add your own samples to
`usare_dataset/cybersec_dataset.jsonl` in this format:

```json
{
  "conversations": [
    {"role": "system", "content": "You are USARE-AI..."},
    {"role": "user", "content": "Your question here"},
    {"role": "assistant", "content": "Expert answer here"}
  ]
}
```

Good sources for additional data:
- NVD API: https://nvd.nist.gov/developers/vulnerabilities
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- HackerOne disclosed reports: https://hackerone.com/hacktivity
- CTF writeups: https://github.com/topics/ctf-writeup
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/

---

## Troubleshooting

**OOM during training:**
- Reduce `batch_size` to 1
- Reduce `lora_r` to 32
- Reduce `max_seq_length` to 2048

**Slow generation on Kaggle:**
- Make sure GPU is selected in notebook settings
- Check `n_gpu_layers=-1` in llama-cpp (all layers on GPU)

**Model not responding correctly:**
- Increase training epochs (try 5)
- Add more domain-specific samples to the dataset
- Check that the chat template is being applied correctly
