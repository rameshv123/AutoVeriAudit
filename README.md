# AutoVeriAudit
Automated Vulnerability Analysis and Security Reporting Framework for Blockchain Smart Contracts
AutoVeriAudit is a research-oriented automated framework designed to enhance smart contract security through structured vulnerability analysis, severity modeling, and automated security reporting. The system integrates verification outputs with intelligent analysis modules to generate explainable risk scores, remediation recommendations, and portfolio-level security insights.
This repository provides a fully reproducible SCI-ready implementation aligned with formal research methodology, enabling large-scale automated auditing workflows.

##  🎯 Key Features

•	Automated batch analysis of multiple smart contracts

•	Feature-based vulnerability severity scoring

•	Dependency-aware risk propagation

•	Explainable scoring with component breakdown

•	Rule-based remediation recommendation engine

•	Multi-format report generation:


o	PDF

o	HTML

o	JSON (API-ready)

•	Portfolio-level dashboard analytics

•	Benchmarking and runtime evaluation

•	Configurable and reproducible pipeline

🧩 System Architecture Overview
AutoVeriAudit follows a layered architecture:
1.	Input Acquisition Layer
Handles contract ingestion, metadata extraction, and batch scheduling.
2.	Verification Integration Layer
Consumes vulnerability outputs from external verification engines.
3.	Automation and Intelligence Layer
Performs feature extraction, severity modeling, classification, and dependency analysis.
4.	Reporting and Delivery Layer
Generates structured reports, dashboards, and machine-readable outputs.

📂 Repository Structure
AutoVeriAudit/
│

├── core/

│       ├── ingestion/        # Contract loading and scheduling

│       ├── verification/     # VeriChain interface wrapper

│       ├── analysis/         # Feature extraction and aggregation

│       ├── scoring/          # Severity modeling and classification

│       ├── remediation/      # Knowledge base and fix engine

│       ├── reporting/        # Report and dashboard generation

│       └── benchmarking/     # Runtime evaluation tools
│

├── pipeline/

│       └── run_pipeline.py   # Main execution workflow
│

├── config/               # Thresholds, weights, schema

├── templates/            # Report templates

├── data/                 # Contracts and outputs

├── utils/                # Logging and helper utilities

└── tests/                # Smoke test

⚙️ Installation
Create a virtual environment and install dependencies:
python -m venv .venv
Windows:
.venv\Scripts\activate
Linux/Mac:
source .venv/bin/activate
Install requirements:
pip install -r requirements.txt

▶️ Running the Framework
Execute the automated pipeline:
python pipeline/run_pipeline.py --contracts_dir data/contracts
The framework will automatically:
•	Load contracts
•	Run vulnerability analysis
•	Compute severity scores
•	Generate remediation recommendations
•	Produce reports and dashboard

📊 Output Files
After execution, results will be generated in:
data/outputs/
Folder	Description
reports	Contract-level PDF and HTML reports
dashboards	Portfolio-level analytics dashboard
json	Machine-readable outputs and manifest
benchmarks	Runtime performance metrics

🧠 Verification Engine Integration
The current implementation includes a mock verification adapter for demonstration purposes.
To integrate a real formal verification tool:
Edit:
core/verification/verichain_interface.py
Replace:
run_verification(contract)
with your verification engine’s output logic.
Expected output:
List[Vulnerability]
Each vulnerability should include:
•	type
•	location
•	description
•	execution trace

🔬 Reproducibility and Configuration
All analytical parameters are externally configurable:
config/weights.yaml       # Severity scoring weights
config/thresholds.yaml    # Risk classification thresholds
config/pipeline_config.yaml
This ensures experiments remain fully reproducible.

📈 Benchmarking Support
AutoVeriAudit automatically records execution timing metrics:
data/outputs/benchmarks/timings.json
These metrics can be used in experimental evaluation sections to report:
•	scalability
•	runtime efficiency
•	automation performance

🧪 Continuous Integration
The repository includes a GitHub Actions workflow that performs:
•	Dependency installation
•	Pipeline smoke testing
•	Output validation

🛡️ Research Scope
This implementation focuses on automated vulnerability analysis and reporting.
Formal verification itself is treated as an external module to maintain modular research design.

📄 Citation
If you use this framework in academic work, please cite:
AutoVeriAudit: An Automated Vulnerability Analysis and Security Reporting Framework for Blockchain Smart Contracts (full paper URL will be provided after publication)
