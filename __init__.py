# BioW-IPP Hardware IP Watermark Detection Package
# LLM-based detection system for identifying counterfeit/pirated hardware IP cores

from .watermark_generator import (
    generate_proteogenomic_watermark,
    encode_dna,
    encode_protein,
    watermark_to_constraints,
    generate_synthetic_rat
)

from .rat_parser import RATParser, ConstraintAnalyzer
from .tampering_generator import TamperingGenerator, TestCaseFormatter
from .llm_detector import LLMDetector, DetectionResult
from .pipeline import BioWIPPPipeline

__version__ = "1.0.0"
__author__ = "BTech Major Project - Group 64"

__all__ = [
    # Watermark generation
    "generate_proteogenomic_watermark",
    "encode_dna",
    "encode_protein",
    "watermark_to_constraints",
    "generate_synthetic_rat",
    # RAT parsing
    "RATParser",
    "ConstraintAnalyzer",
    # Tampering
    "TamperingGenerator",
    "TestCaseFormatter",
    # Detection
    "LLMDetector",
    "DetectionResult",
    # Pipeline
    "BioWIPPPipeline"
]