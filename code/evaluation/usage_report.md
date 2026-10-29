# Token and cost usage report — Ghost Data Still Exists

## Final full-dataset run

The local pipeline processes the full participant request CSV using deterministic Python code and the Python standard library. It does not call a hosted or local LLM, does not make API calls, and does not transmit dataset content outside the workspace.

| Provider / model | Calls | Input tokens | Output tokens | Total tokens | Cost |
|---|---:|---:|---:|---:|---:|
| None (deterministic local Python) | 0 | 0 | 0 | 0 | $0.00 |
| **Overall** | **0** | **0** | **0** | **0** | **$0.00** |

- Dataset requests processed by the final run: 518.
- Total/average tokens per request: 0 / 0.
- Estimated total/per-request model cost: $0.00 / $0.00.
- Per-model and overall totals are identical because no model was used.

The optional `pdftotext` executable is invoked locally for text extraction when installed; it is not a model provider and incurs no model-token cost. This report is limited to the final command-line run and makes no claim about tokens consumed during interactive development.
