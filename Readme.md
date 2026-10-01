NextGen Editor — The Google Cloud Next '27 Prep Agent 🚀

NextGen Editor is an AI-powered editorial and speaker-preparation agent built with the Google GenAI SDK (google-genai), instrumented with OpenTelemetry (opentelemetry-api, opentelemetry-sdk), tested with pytest, and provisioned on Google Cloud via Terraform.

It helps speakers, sales leaders, and product teams craft high-impact session proposals, verify brand and product terminology, and build structured keynote/breakout talking points for Google Cloud Next '27.

Key Capabilities & Tools
Session Proposal & Abstract Reviewer (review_session_abstract)
Evaluates draft abstracts against Google Cloud Next '27 track criteria (Agentic AI & Gemini Enterprise, AI Hypercomputer & Infrastructure, Data Cloud & Analytics, Cybersecurity & Sovereign Cloud, Customer Transformation & Executive Track).
Computes a readiness_score (0–100) and provides actionable editorial suggestions on length, quantifiable ROI metrics, and attendee takeaways.
Brand & Terminology Compliance Checker (check_brand_and_style_guidelines)
Scans proposals and speaker scripts for deprecated naming (e.g., flagging legacy terms and recommending current naming like Gemini Enterprise and Vertex AI Agent Builder).
Speaker Run-of-Show Generator (generate_speaker_talking_points)
Generates a timed presentation breakdown (Hook, Solution Architecture, Live Demo, ROI & Q&A) and executive soundbites tailored to the target audience persona.
Built-In OpenTelemetry Observability
Every agent run (nextgen_editor_agent.run) and tool invocation emits structured OpenTelemetry trace spans with session metadata and readiness scores.
Architecture
Repository Structure
text
nextgen-editor-agent/
├── src/
│   ├── __init__.py
│   └── agent.py          # NextGen Editor Agent, tools, and OpenTelemetry tracing
├── tests/
│   └── test_agent.py     # Unit test suite (pytest / unittest compatible)
├── terraform/
│   ├── main.tf           # Cloud Run v2, Vertex AI, Cloud Trace, and IAM resources
│   ├── variables.tf      # Configurable GCP project, region, and image variables
│   └── outputs.tf        # Deployed service URL and Service Account outputs
├── requirements.txt      # Python dependencies (pytest, google-genai, opentelemetry)
└── README.md             # Project documentation
Quick Start
1. Set Up Environment & Install Dependencies
bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
2. Run the Agent
bash
python3 -m src.agent

(Optional) To use live Gemini generation, export GEMINI_API_KEY="your-api-key" or configure Vertex AI (GOOGLE_GENAI_USE_VERTEXAI=true). Set OTEL_LOG_SPANS=true to print OpenTelemetry spans to the console.

3. Run Unit Tests
bash
pytest
# Or using standard library unittest:
python3 -m unittest discover -s tests -v
4. Provision Infrastructure with Terraform
bash
cd terraform
terraform init
terraform plan -var="project_id=your-gcp-project-id"
terraform apply -var="project_id=your-gcp-project-id"
Jetski
expires: Oct 5 at 6:06 PM
20261001.01_p0 | 2026.09.29.04
