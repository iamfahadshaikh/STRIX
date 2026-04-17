# Architecture Overview

## Purpose

VAPT Automated Engine orchestrates discovery, validation, and reporting across multiple security tools with confidence and evidence controls.

## Pipeline

1. Target profiling
2. Decision ledger build
3. Discovery and crawling
4. Signal-driven gating
5. Exploitation validation
6. Correlation and deduplication
7. Risk scoring and report generation

## Core Principles

- Evidence-first findings
- Reduced false positives
- Deterministic reporting output
- Safe defaults and explicit target scope
- Resilience under tool failures and timeouts

## Key Components

- Orchestrator
- Discovery cache
- Tool manager and parser layer
- Confidence and risk engines
- Proof-based reporter
- HTML and JSON report generators
