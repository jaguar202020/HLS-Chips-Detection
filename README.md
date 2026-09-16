# BioW-IPP Hardware IP Watermark Detection System

LLM-based detection pipeline for identifying counterfeit/pirated hardware IP cores secured by proteogenomic bio-watermarking during High-Level Synthesis.

## Overview

This implementation provides a complete detection system based on the BioW-IPP research paper (Sengupta, Bhui, Chourasia; Scientific Reports 2025). It demonstrates how to:

1. Generate a 445-bit proteogenomic watermark from DNA and insulin protein sequences
2. Parse Register Allocation Tables (RAT) from HLS designs
3. Generate synthetic tampering scenarios for testing
4. Use LLM to classify designs as authentic/suspicious/pirated

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

```python
from biowipp_detector import BioWIPPPipeline

# Initialize with vendor's biological sequences
pipeline = BioWIPPPipeline(
    dna_sequence="ATGCGATCG" * 28,
    alpha_chain="MALWMRLLPLL" + "A" * 70,
    beta_chain="MALWMRLLPLLALLALWGPDP" + "A" * 95,
    use_mock_llm=True  # Set False to use real LLM API
)

# Generate test cases
test_scenarios = pipeline.generate_test_cases(samples_per_type=10)

# Run evaluation
metrics = pipeline.run_evaluation(test_scenarios)

# Print report
print(pipeline.generate_report(metrics))
```

## Module Structure

| Module | Description |
|--------|-------------|
| `watermark_generator.py` | Converts DNA/protein sequences to 445-bit watermark |
| `rat_parser.py` | Parses Register Allocation Tables from HLS |
| `tampering_generator.py` | Generates synthetic piracy test scenarios |
| `llm_detector.py` | LLM-based classification of designs |
| `pipeline.py` | Complete end-to-end detection pipeline |

## How It Works

### 1. Watermark Generation
- DNA sequence → 248 bits (A=00, C=01, G=10, T=11)
- Insulin Alpha chain → 81 bits (amino acid encoding)
- Insulin Beta chain → 116 bits (amino acid encoding)
- Combined: 81 + 248 + 116 = **445 bits**

### 2. Constraint Mapping
- Bit 0 → even-even pair (V0, V2), (V2, V4), ...
- Bit 1 → odd-odd pair (V1, V3), (V3, V5), ...
- These pairs cannot share physical registers

### 3. Detection
- Extract constraints from recovered RAT
- Reconstruct watermark bits from constraints
- Compare against vendor's expected watermark
- LLM classifies: AUTHENTIC / SUSPICIOUS / PIRATED

## Testing with Mock LLM

The system includes a mock LLM for demonstration without API access:

```python
# Mock mode (default) - uses rule-based classification
detector = LLMDetector(watermark, use_mock=True)

# Real LLM mode - requires API configuration
detector = LLMDetector(watermark, use_mock=False)
```

## Real LLM Integration

To use with actual LLM APIs (OpenAI, Anthropic, etc.):

```python
# Configure in llm_detector.py _real_llm_classify method
# Currently placeholder for API integration
```

## Demo

Run the demo:

```bash
python -m biowipp_detector.pipeline
```

Sample output:
```
============================================================
BioW-IPP LLM Detection Pipeline - Demo
============================================================

Step 1: Initialize Pipeline
[Pipeline] Generated 445-bit watermark
[Pipeline] Extracted 445 watermark constraints

Step 2: Generate Test Scenarios
[Pipeline] Generated test cases:
  - authentic: 5 samples
  - modified_register: 5 samples
  - partial_watermark: 5 samples
  ...

Step 3: Run Evaluation
[Pipeline] Running evaluation on 35 test cases...
[Pipeline] Evaluation complete!
  Accuracy: 94.3%
  Avg Confidence: 0.87
```

## For Demo

This implementation can be demonstrated without actual hardware data:

1. **Synthetic RAT Generation**: Creates realistic register allocation tables
2. **Tampering Simulation**: Generates modified designs (pirated, tampered, authentic)
3. **Detection Accuracy**: Shows high accuracy in identifying tampered designs

The professor can provide actual hardware design datasets later for real-world validation.

## References

- Sengupta, A., Bhui, P.M.A., Chourasia, A. (2025). Hardware IP protection by exploiting IP vendor's proteogenomic bio-marker as digital watermark during behavioral synthesis. Scientific Reports, 15:12718.
