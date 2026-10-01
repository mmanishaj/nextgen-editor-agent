        session_title="Agentic Transformation at Scale",
        audience_persona="CIOs & Sales Leaders",
        duration_minutes=45,
    )
    self.assertEqual(outline["duration_minutes"], 45)
    self.assertEqual(len(outline["run_of_show"]), 4)
  def test_agent_run_end_to_end(self):
    agent = NextGenEditorAgent()
    output = agent.run(
        prompt="Prepare our session proposal for Google Cloud Next '27."
    )
    self.assertEqual(
        output["agent_name"],
        "NextGen Editor — The Google Cloud Next '27 Prep Agent",
    )
    self.assertIn("review", output)
    self.assertIn("style_check", output)
    self.assertIn("talking_points", output)
    self.assertIn("NextGen Editor", output["editorial_summary"])
if __name__ == "__main__":
  unittest.main()
Jetski
expires: Oct 5 at 6:06 PM
20261001.01_p0 | 2026.09.29.04
