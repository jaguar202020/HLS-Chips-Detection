# BioW-IPP LLM Detection Pipeline
# Main orchestration module for the complete watermark detection system

import json
import random
from typing import Dict, List, Tuple, Optional

from watermark_generator import (
    generate_proteogenomic_watermark,
    watermark_to_constraints,
    generate_synthetic_rat
)
from rat_parser import RATParser, ConstraintAnalyzer
from tampering_generator import TamperingGenerator, TestCaseFormatter
from llm_detector import LLMDetector, DetectionResult


class BioWIPPPipeline:
    """Complete pipeline for BioW-IPP watermark detection using LLM."""

    def __init__(self, dna_sequence: str, alpha_chain: str, beta_chain: str,
                 use_mock_llm: bool = False, llm_model: str = "Qwen/Qwen3-4B"):
        """
        Initialize the detection pipeline.

        Args:
            dna_sequence: Vendor's DNA sequence
            alpha_chain: Insulin Alpha chain amino acid sequence
            beta_chain: Insulin Beta chain amino acid sequence
            use_mock_llm: Use the rule-based mock instead of the local Qwen model
            llm_model: Hugging Face model ID or local path for Qwen3
        """
        # Generate vendor's watermark
        self.watermark = generate_proteogenomic_watermark(
            dna_sequence, alpha_chain, beta_chain
        )
        print(f"[Pipeline] Generated {len(self.watermark)}-bit watermark")

        # Extract expected constraints
        self.constraints = watermark_to_constraints(self.watermark)
        print(f"[Pipeline] Extracted {len(self.constraints)} watermark constraints")

        # Initialize components
        self.detector = LLMDetector(
            self.watermark,
            use_mock=use_mock_llm,
            model_name=llm_model
        )
        self.rat_parser = RATParser()

    def load_rat(self, rat_data: Dict) -> bool:
        """Load and parse a RAT for analysis."""
        return self.rat_parser.parse_from_dict(rat_data)

    def analyze_current_rat(self) -> DetectionResult:
        """Analyze the currently loaded RAT."""
        return self.detector.analyze_rat(
            self.rat_parser.assignments,
            self.rat_parser
        )

    def analyze_rat_data(self, rat_data: Dict) -> DetectionResult:
        """Analyze a RAT dictionary directly."""
        return self.detector.analyze_rat(rat_data)

    def generate_test_cases(self, samples_per_type: int = 10) -> Dict[str, List[Dict]]:
        """
        Generate synthetic test cases for evaluation.

        Args:
            samples_per_type: Number of samples per tampering type

        Returns:
            Dictionary of test scenarios
        """
        # Generate base RAT
        base_rat = generate_synthetic_rat(
            num_variables=892,
            num_control_steps=31
        )

        # Add all watermark constraints to the synthetic base RAT
        for v1, v2, ctype in self.constraints:
            v1_name = f"V{v1}"
            v2_name = f"V{v2}"

            if v1_name in base_rat['assignments'] and v2_name in base_rat['assignments']:
                # Ensure they don't share registers
                if base_rat['assignments'][v1_name]['register'] == \
                   base_rat['assignments'][v2_name]['register']:
                    # Assign different registers
                    base_rat['assignments'][v2_name]['register'] = \
                        (base_rat['assignments'][v2_name]['register'] + 1) % 137

        # Generate tampering scenarios
        generator = TamperingGenerator(base_rat, self.watermark)
        scenarios = generator.generate_all_scenarios(samples_per_type)

        print(f"[Pipeline] Generated test cases:")
        for scenario_type, rats in scenarios.items():
            print(f"  - {scenario_type}: {len(rats)} samples")

        return scenarios

    def run_evaluation(self, test_scenarios: Dict[str, List[Dict]]) -> Dict:
        """
        Run complete evaluation on test scenarios.

        Args:
            test_scenarios: Dictionary of tampered RAT scenarios

        Returns:
            Evaluation metrics dictionary
        """
        # Flatten dataset with labels
        dataset = []
        for label, rats in test_scenarios.items():
            for rat in rats:
                dataset.append((rat, label))

        random.shuffle(dataset)

        print(f"[Pipeline] Running evaluation on {len(dataset)} test cases...")

        # Run detection on all samples
        results = self.detector.batch_analyze(dataset)

        # Evaluate accuracy
        metrics = self.detector.evaluate_accuracy(results)

        print(f"[Pipeline] Evaluation complete!")
        print(f"  Accuracy: {metrics['accuracy']*100:.1f}%")
        print(f"  Avg Confidence: {metrics['avg_confidence']:.2f}")

        return metrics

    def generate_report(self, metrics: Dict) -> str:
        """Generate evaluation report."""
        report = []
        report.append("=" * 60)
        report.append("BioW-IPP LLM Detection Pipeline - Evaluation Report")
        report.append("=" * 60)
        report.append("")

        report.append(f"Watermark Length: {len(self.watermark)} bits")
        report.append(f"Expected Constraints: {len(self.constraints)}")
        report.append("")

        report.append("--- Detection Performance ---")
        report.append(f"Overall Accuracy: {metrics['accuracy']*100:.1f}%")
        report.append(f"Correct Predictions: {metrics['correct']}/{metrics['total']}")
        report.append(f"Average Confidence: {metrics['avg_confidence']:.2f}")
        report.append("")

        report.append("--- Confusion Matrix ---")
        cm = metrics['confusion_matrix']
        report.append("                 Predicted")
        report.append("                 Authentic  Suspicious  Pirated")
        report.append(f"Actual Authentic    {cm['authentic']['authentic']:4d}       {cm['authentic']['suspicious']:4d}       {cm['authentic']['pirated']:4d}")
        report.append(f"       Suspicious   {cm['suspicious']['authentic']:4d}       {cm['suspicious']['suspicious']:4d}       {cm['suspicious']['pirated']:4d}")
        report.append(f"       Pirated      {cm['pirated']['authentic']:4d}       {cm['pirated']['suspicious']:4d}       {cm['pirated']['pirated']:4d}")
        report.append("")

        report.append("=" * 60)

        return "\n".join(report)


def run_demo():
    """Run a complete demonstration of the pipeline."""
    print("=" * 60)
    print("BioW-IPP LLM Detection Pipeline - Demo")
    print("=" * 60)
    print()

    # Sample vendor sequences (simplified for demo)
    # In real use, these would come from vendor's actual biological samples
    dna_sequence = "ATGCGATCG" * 28 + "ATGC"  # 248 bits worth
    alpha_chain = "MALWMRLLPLL" + "A" * 70    # 81 bits worth
    beta_chain = "MALWMRLLPLLALLALWGPDP" + "A" * 95  # 116 bits worth

    print("Step 1: Initialize Pipeline")
    print("-" * 40)
    pipeline = BioWIPPPipeline(
        dna_sequence=dna_sequence,
        alpha_chain=alpha_chain,
        beta_chain=beta_chain,
        use_mock_llm=False  # Use local Qwen3; set True for the rule-based demo
    )
    print()

    print("Step 2: Generate Test Scenarios")
    print("-" * 40)
    test_scenarios = pipeline.generate_test_cases(samples_per_type=5)
    print()

    print("Step 3: Run Evaluation")
    print("-" * 40)
    metrics = pipeline.run_evaluation(test_scenarios)
    print()

    print("Step 4: Generate Report")
    print("-" * 40)
    report = pipeline.generate_report(metrics)
    print(report)

    # Demonstrate single RAT analysis
    print("\nStep 5: Single RAT Analysis Demo")
    print("-" * 40)

    # Get authentic sample
    authentic_rat = test_scenarios['authentic'][0]
    result = pipeline.analyze_rat_data(authentic_rat)

    print(f"Classification: {result.classification.upper()}")
    print(f"Confidence: {result.confidence:.2f}")
    print(f"Watermark Match Rate: {result.watermark_match_rate*100:.1f}%")
    print(f"Reasoning: {result.reasoning[:300]}...")

    return pipeline, metrics


def create_sample_rat_from_template():
    """Create a realistic sample RAT based on JPEG-CODEC benchmark."""
    # Simulating 273 variables across 31 control steps
    # Using the same structure as Table 2 from the paper
    variables = []
    assignments = {}

    for i in range(273):
        # Lifetime: varies from 2 to 15 control steps
        start = random.randint(0, 20)
        lifetime = random.randint(2, min(12, 31 - start))
        end = min(start + lifetime, 30)

        var_name = f"V{i}"
        variables.append({
            'name': var_name,
            'start': start,
            'end': end,
            'type': 'temp' if random.random() > 0.2 else 'accumulator'
        })

        # Register assignment (137 registers for JPEG-CODEC)
        reg = random.randint(0, 136)
        assignments[var_name] = {
            'register': reg,
            'control_steps': list(range(start, end + 1))
        }

    return {
        'num_variables': 273,
        'num_control_steps': 31,
        'variables': variables,
        'assignments': assignments
    }


if __name__ == "__main__":
    run_demo()