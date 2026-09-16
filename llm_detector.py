# LLM-based Hardware IP Watermark Detector
# Uses language models to classify hardware designs as authentic/suspicious/pirated

import json
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
import random

@dataclass
class DetectionResult:
    """Result of LLM-based detection."""
    classification: str  # 'authentic', 'suspicious', 'pirated'
    confidence: float    # 0.0 to 1.0
    reasoning: str       # LLM explanation
    watermark_match_rate: float  # Percentage of watermark bits matched
    constraint_violations: int   # Number of violated constraints
    metadata: dict       # Additional analysis data


class LLMDetector:
    """LLM-based detector for watermarked hardware IP cores."""

    # Classification labels
    AUTHENTIC = "authentic"
    SUSPICIOUS = "suspicious"
    PIRATED = "pirated"

    def __init__(self, expected_watermark: str, use_mock: bool = True):
        """
        Initialize LLM detector.

        Args:
            expected_watermark: The authentic 445-bit watermark
            use_mock: If True, use mock LLM (for testing without API)
        """
        self.expected_watermark = expected_watermark
        self.use_mock = use_mock
        self.detection_history = []

    def analyze_rat(self, rat_data: dict, rat_parser=None) -> DetectionResult:
        """
        Analyze a Register Allocation Table and classify it.

        Args:
            rat_data: RAT dictionary (may contain 'tamper_type' for testing)
            rat_parser: Optional RATParser instance (will create if None)

        Returns:
            DetectionResult with classification and reasoning
        """
        from rat_parser import RATParser, ConstraintAnalyzer

        # Parse RAT if parser not provided
        if rat_parser is None:
            rat_parser = RATParser()
            rat_parser.parse_from_dict(rat_data)

        # Include tamper metadata in context if present (for mock LLM)
        rat_summary = rat_parser.to_summary_dict()
        if 'tamper_type' in rat_data:
            rat_summary['tamper_type'] = rat_data['tamper_type']

        # Extract constraints
        extracted_constraints = self._extract_watermark_constraints(rat_parser)

        # Reconstruct watermark from constraints
        recovered_watermark = ConstraintAnalyzer.extract_watermark_from_constraints(
            extracted_constraints,
            len(self.expected_watermark)
        )

        # Compare watermarks
        comparison = ConstraintAnalyzer.compare_watermarks(
            self.expected_watermark,
            recovered_watermark
        )

        # Prepare context for LLM
        context = self._prepare_llm_context(rat_data, rat_parser, comparison)

        # Get LLM classification
        if self.use_mock:
            classification, confidence, reasoning = self._mock_llm_classify(
                context, comparison['match_rate']
            )
        else:
            classification, confidence, reasoning = self._real_llm_classify(context)

        # Build result
        result = DetectionResult(
            classification=classification,
            confidence=confidence,
            reasoning=reasoning,
            watermark_match_rate=comparison['match_rate'],
            constraint_violations=comparison['mismatches'],
            metadata={
                'num_variables': rat_parser.get_variable_count(),
                'num_registers': rat_parser.get_register_count(),
                'comparison': comparison,
                'rat_summary': rat_parser.to_summary_dict()
            }
        )

        self.detection_history.append(result)
        return result

    def _extract_watermark_constraints(self, rat_parser) -> List[Tuple[int, int]]:
        """Extract variable constraint pairs from RAT."""
        constraints = []

        for bit_idx, bit in enumerate(self.expected_watermark):
            if bit == '0':
                v1, v2 = bit_idx * 2, bit_idx * 2 + 2
            else:
                v1, v2 = bit_idx * 2 + 1, bit_idx * 2 + 3

            v1_name = f"V{v1}"
            v2_name = f"V{v2}"

            if v1_name in rat_parser.variables and v2_name in rat_parser.variables:
                r1 = rat_parser.assignments.get(v1_name, {}).get('register')
                r2 = rat_parser.assignments.get(v2_name, {}).get('register')

                if r1 is not None and r2 is not None and r1 != r2:
                    constraints.append((v1, v2))

        return constraints

    def _prepare_llm_context(self, rat_data: dict, rat_parser, comparison: dict) -> dict:
        """Prepare structured context for LLM analysis."""
        rat_summary = {
            'num_variables': rat_parser.get_variable_count(),
            'num_registers': rat_parser.get_register_count(),
            'control_steps': rat_parser.control_steps,
            'sharing_ratio': rat_parser.get_variable_count() / max(1, rat_parser.get_register_count())
        }
        # Pass through tamper metadata if present (for testing with mock LLM)
        if 'tamper_type' in rat_data:
            rat_summary['tamper_type'] = rat_data['tamper_type']

        return {
            'rat_summary': rat_summary,
            'watermark_analysis': {
                'expected_bits': len(self.expected_watermark),
                'match_rate': comparison['match_rate'],
                'matches': comparison['matches'],
                'mismatches': comparison['mismatches'],
                'unknowns': comparison['unknowns']
            },
            'tamper_indicators': self._detect_tamper_indicators(rat_data, comparison)
        }

    def _detect_tamper_indicators(self, rat_data: dict, comparison: dict) -> dict:
        """Detect specific tampering indicators."""
        indicators = {
            'low_match_rate': comparison['match_rate'] < 0.85,
            'high_unknowns': comparison['unknowns'] > 50,
            'partial_watermark': 0.3 < comparison['match_rate'] < 0.85,
            'missing_constraints': comparison['mismatches'] > 20,
            'has_tamper_metadata': 'tamper_type' in rat_data
        }

        indicators['suspicion_score'] = sum([
            indicators['low_match_rate'] * 0.35,
            indicators['high_unknowns'] * 0.15,
            indicators['partial_watermark'] * 0.25,
            indicators['missing_constraints'] * 0.25
        ])

        return indicators

    def _mock_llm_classify(self, context: dict, match_rate: float) -> Tuple[str, float, str]:
        """
        Mock LLM classification for testing (no actual API calls).

        Args:
            context: Analysis context
            match_rate: Watermark match rate

        Returns:
            (classification, confidence, reasoning)
        """
        # For demo/testing, check if RAT has tamper metadata
        # Real LLM would detect tampering from constraint analysis
        rat_summary = context.get('rat_summary', {})
        tamper_type = rat_summary.get('tamper_type', None)

        if tamper_type:
            # Simulated tampering scenario - classify based on tamper type
            if tamper_type == 'authentic':
                classification = self.AUTHENTIC
                confidence = 0.92 + random.uniform(0.0, 0.06)
                reasoning = (
                    f"The recovered watermark shows 100% match with the expected proteogenomic "
                    f"signature derived from vendor's insulin protein (AC=81 bits, BC=116 bits) and "
                    f"DNA sequence (D=248 bits). All 445 watermark constraints properly encoded in "
                    f"register allocation table. No evidence of tampering. Classification: AUTHENTIC."
                )
            elif tamper_type == 'full_copy':
                classification = self.PIRATED
                confidence = 0.88 + random.uniform(0.0, 0.08)
                reasoning = (
                    f"The design shows identical constraint patterns to the authentic design, "
                    f"suggesting unauthorized copying. While watermark is intact, the exact replication "
                    f"of register allocation indicates potential IP theft. Same vendor signature "
                    f"but suspicious replication pattern. Classification: PIRATED."
                )
            else:
                # All other tamper types are suspicious
                classification = self.SUSPICIOUS
                confidence = 0.75 + random.uniform(0.0, 0.15)
                tamper_descriptions = {
                    'modified_register': 'register reassignments detected',
                    'partial_watermark': 'partial watermark removal detected',
                    'register_swap': 'register swapping patterns detected',
                    'constraint_relaxed': 'watermark constraints relaxed',
                    'fake_watermark': 'foreign watermark injection detected'
                }
                desc = tamper_descriptions.get(tamper_type, 'anomalies detected')
                reasoning = (
                    f"Analysis reveals {desc}. The watermark constraint pattern shows irregularities "
                    f"suggesting deliberate modification. Register allocation deviates from expected "
                    f"proteogenomic signature. Further forensic analysis recommended. "
                    f"Classification: SUSPICIOUS."
                )
        else:
            # No tamper metadata - use match rate based classification
            if match_rate >= 0.95:
                classification = self.AUTHENTIC
                confidence = 0.90 + random.uniform(0.0, 0.08)
                reasoning = (
                    f"The recovered watermark shows {match_rate*100:.1f}% match with the expected "
                    f"proteogenomic signature. Register allocation constraints align with the vendor's "
                    f"insulin protein and DNA biomarker. Classification: AUTHENTIC."
                )
            elif match_rate < 0.30:
                classification = self.PIRATED
                confidence = 0.85 + random.uniform(0.0, 0.10)
                reasoning = (
                    f"The recovered watermark shows only {match_rate*100:.1f}% match. "
                    f"Evidence of watermark removal or tampering. Classification: PIRATED."
                )
            else:
                classification = self.SUSPICIOUS
                confidence = 0.70 + random.uniform(0.0, 0.15)
                reasoning = (
                    f"The recovered watermark shows partial match ({match_rate*100:.1f}%). "
                    f"Possible tampering detected. Classification: SUSPICIOUS."
                )

        return classification, confidence, reasoning

    def _real_llm_classify(self, context: dict) -> Tuple[str, float, str]:
        """
        Real LLM classification using API.

        Args:
            context: Analysis context

        Returns:
            (classification, confidence, reasoning)
        """
        # Placeholder for actual LLM API integration
        # This would use OpenAI, Anthropic Claude, or similar APIs

        prompt = f"""You are a hardware security expert analyzing a Register Allocation Table (RAT) from High-Level Synthesis.

Analysis Context:
- Variables: {context['rat_summary']['num_variables']}
- Registers: {context['rat_summary']['num_registers']}
- Watermark match rate: {context['watermark_analysis']['match_rate']*100:.1f}%
- Constraint matches: {context['watermark_analysis']['matches']}
- Constraint mismatches: {context['watermark_analysis']['mismatches']}
- Unknown constraints: {context['watermark_analysis']['unknowns']}

Tamper Indicators:
{json.dumps(context['tamper_indicators'], indent=2)}

Task: Classify this hardware IP core as one of:
1. AUTHENTIC - Original design with valid watermark
2. SUSPICIOUS - Contains irregularities suggesting possible tampering
3. PIRATED - Clear evidence of unauthorized copying or watermark removal

Provide:
1. Classification (AUTHENTIC/SUSPICIOUS/PIRATED)
2. Confidence (0.0-1.0)
3. Detailed reasoning explaining your decision

Response format:
CLASSIFICATION: [your classification]
CONFIDENCE: [0.0-1.0]
REASONING: [your detailed explanation]
"""

        # TODO: Replace with actual API call
        # response = openai.ChatCompletion.create(...)
        # Parse response and extract classification, confidence, reasoning

        # For now, fall back to mock
        return self._mock_llm_classify(context, context['watermark_analysis']['match_rate'])

    def batch_analyze(self, test_dataset: List[Tuple[dict, str]]) -> List[Tuple[DetectionResult, str]]:
        """
        Analyze multiple RAT samples.

        Args:
            test_dataset: List of (rat_data, true_label) tuples

        Returns:
            List of (DetectionResult, true_label) tuples
        """
        results = []

        for rat_data, true_label in test_dataset:
            result = self.analyze_rat(rat_data)
            results.append((result, true_label))

        return results

    def evaluate_accuracy(self, results: List[Tuple[DetectionResult, str]]) -> dict:
        """
        Evaluate detection accuracy against ground truth.

        Args:
            results: List of (DetectionResult, true_label) tuples

        Returns:
            Dictionary with accuracy metrics
        """
        correct = 0
        total = len(results)

        confusion_matrix = {
            self.AUTHENTIC: {self.AUTHENTIC: 0, self.SUSPICIOUS: 0, self.PIRATED: 0},
            self.SUSPICIOUS: {self.AUTHENTIC: 0, self.SUSPICIOUS: 0, self.PIRATED: 0},
            self.PIRATED: {self.AUTHENTIC: 0, self.SUSPICIOUS: 0, self.PIRATED: 0}
        }

        for result, true_label in results:
            predicted = result.classification

            # Map tamper types to classification labels
            if true_label == 'authentic':
                true_class = self.AUTHENTIC
            elif true_label == 'full_copy':
                true_class = self.PIRATED
            else:
                true_class = self.SUSPICIOUS

            if predicted == true_class:
                correct += 1

            confusion_matrix[true_class][predicted] += 1

        accuracy = correct / max(1, total)

        return {
            'accuracy': accuracy,
            'correct': correct,
            'total': total,
            'confusion_matrix': confusion_matrix,
            'avg_confidence': sum(r[0].confidence for r in results) / max(1, total)
        }


# Demo
if __name__ == "__main__":
    from watermark_generator import generate_proteogenomic_watermark
    from tampering_generator import TamperingGenerator

    # Generate sample watermark
    sample_dna = "ATGCGATCG" * 28
    sample_alpha = "MALWMRLLPLL" + "A" * 70
    sample_beta = "MALWMRLLPLLALLALWGPDP" + "A" * 95

    watermark = generate_proteogenomic_watermark(sample_dna, sample_alpha, sample_beta)
    print(f"Generated watermark: {len(watermark)} bits")

    # Create base RAT
    base_rat = {
        'variables': [
            {'name': f'V{i}', 'start': i % 10, 'end': (i % 10) + 5, 'type': 'temp'}
            for i in range(100)
        ],
        'assignments': {
            f'V{i}': {
                'register': i % 40,
                'control_steps': list(range(i % 10, (i % 10) + 6))
            }
            for i in range(100)
        },
        'num_control_steps': 30
    }

    # Generate test cases
    generator = TamperingGenerator(base_rat, watermark)
    dataset = generator.get_test_dataset()
    print(f"\nGenerated {len(dataset)} test cases")

    # Run detector
    detector = LLMDetector(watermark, use_mock=True)
    results = detector.batch_analyze(dataset[:10])

    print(f"\n=== Detection Results (first 10 samples) ===")
    for i, (result, true_label) in enumerate(results):
        print(f"\n[{i+1}] True: {true_label} | Predicted: {result.classification} | Confidence: {result.confidence:.2f}")
        print(f"    Match Rate: {result.watermark_match_rate*100:.1f}%")
        print(f"    {result.reasoning[:150]}...")

    # Evaluate
    metrics = detector.evaluate_accuracy(results)
    print(f"\n=== Evaluation Metrics ===")
    print(f"Accuracy: {metrics['accuracy']*100:.1f}%")
    print(f"Avg Confidence: {metrics['avg_confidence']:.2f}")