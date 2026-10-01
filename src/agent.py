"""NextGen Editor — The Google Cloud Next '27 Prep Agent."""

from contextlib import nullcontext
import os
from typing import Any

try:
  from opentelemetry import trace
  from opentelemetry.sdk.trace import TracerProvider

  if not isinstance(trace.get_tracer_provider(), TracerProvider):
    trace.set_tracer_provider(TracerProvider())
  tracer = trace.get_tracer("nextgen.editor.agent")
except ImportError:

  class _NoOpTracer:
    def start_as_current_span(self, name: str):
      return nullcontext()

  tracer = _NoOpTracer()


def review_session_abstract(title: str, abstract: str) -> dict[str, Any]:
  """Reviews a Google Cloud Next '27 session proposal for clarity and impact."""
  with tracer.start_as_current_span("tool.review_session_abstract"):
    word_count = len(abstract.strip().split())
    score = 90 if word_count >= 25 else 65
    return {
        "session_title": title,
        "word_count": word_count,
        "readiness_score": score,
        "status": "READY_FOR_SUBMISSION" if score >= 80 else "NEEDS_REVISION",
    }


def check_brand_and_style_guidelines(content: str) -> dict[str, Any]:
  """Checks draft text against Google Cloud Next '27 naming guidelines."""
  with tracer.start_as_current_span("tool.check_brand_and_style_guidelines"):
    outdated = [t for t in ("duet ai", "bard") if t in content.lower()]
    return {"is_compliant": len(outdated) == 0, "issues_found": len(outdated)}


def generate_speaker_talking_points(
    session_title: str, duration_minutes: int = 45
) -> dict[str, Any]:
  """Generates a structured Google Cloud Next '27 speaker outline."""
  with tracer.start_as_current_span("tool.generate_speaker_talking_points"):
    return {
        "session_title": session_title,
        "duration_minutes": duration_minutes,
        "run_of_show": [
            "10 min — The Hook: Customer Challenge for Next '27",
            "15 min — Solution Architecture with Gemini Enterprise",
            "10 min — Live Agent Demo",
            "10 min — Measurable ROI & Takeaways",
        ],
    }


class NextGenEditorAgent:
  """NextGen Editor — The Google Cloud Next '27 Prep Agent."""

  def __init__(self, model_name: str = "gemini-2.5-flash"):
    self.name = "NextGen Editor — The Google Cloud Next '27 Prep Agent"
    self.model_name = model_name

  def run(
      self,
      prompt: str,
      title: str = "Scaling Enterprise AI Agents at Google Cloud Next '27",
      abstract: str = (
          "Learn how global enterprises deploy production AI agents with "
          "Gemini Enterprise and Vertex AI Agent Builder to achieve 35% faster "
          "customer resolution and 3x ROI."
      ),
  ) -> dict[str, Any]:
    with tracer.start_as_current_span("nextgen_editor_agent.run"):
      review = review_session_abstract(title, abstract)
      style = check_brand_and_style_guidelines(f"{title}\n{abstract}")
      talking_points = generate_speaker_talking_points(title)

      if os.environ.get("GEMINI_API_KEY"):
        from google import genai
        client = genai.Client()
        resp = client.models.generate_content(model=self.model_name, contents=prompt)
        summary = resp.text
      else:
        summary = f"[{self.name}] '{title}' scored {review['readiness_score']}/100."

      return {
          "agent_name": self.name,
          "review": review,
          "style_check": style,
          "talking_points": talking_points,
          "editorial_summary": summary,
      }


if __name__ == "__main__":
  print(NextGenEditorAgent().run("Prepare our Next '27 session proposal."))   
