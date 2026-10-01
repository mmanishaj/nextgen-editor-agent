"""Unit tests for NextGen Editor — The Google Cloud Next '27 Prep Agent."""

import unittest
from src.agent import (
    NextGenEditorAgent,
    check_brand_and_style_guidelines,
    generate_speaker_talking_points,
    review_session_abstract,
)


class TestNextGenEditorAgent(unittest.TestCase):

  def test_agent_identity(self):
    agent = NextGenEditorAgent()
    self.assertEqual(
        agent.name, "NextGen Editor — The Google Cloud Next '27 Prep Agent"
    )

  def test_review_session_abstract(self):
    res = review_session_abstract(
        "Next '27 Keynote",
        "Learn how enterprises use Gemini Enterprise and Vertex AI Agent Builder "
        "to deliver 40% faster support resolution and 3x ROI across teams.",
    )
    self.assertEqual(res["status"], "READY_FOR_SUBMISSION")

  def test_brand_guidelines(self):
    self.assertFalse(check_brand_and_style_guidelines("Uses Duet AI")["is_compliant"])
    self.assertTrue(check_brand_and_style_guidelines("Uses Gemini Enterprise")["is_compliant"])

  def test_talking_points_and_run(self):
    outline = generate_speaker_talking_points("Next '27 Session", 45)
    self.assertEqual(len(outline["run_of_show"]), 4)
    output = NextGenEditorAgent().run("Review our Next '27 session")
    self.assertIn("NextGen Editor", output["editorial_summary"])


if __name__ == "__main__":
  unittest.main()
