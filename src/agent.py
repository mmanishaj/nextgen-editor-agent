          "review": review,
          "style_check": style,
          "talking_points": talking_points,
          "editorial_summary": llm_summary,
      }
if __name__ == "__main__":
  agent = NextGenEditorAgent()
  result = agent.run(
      prompt="Review our Google Cloud Next '27 session proposal and create a 45-min speaker outline."
  )
  print("=" * 72)
  print(result["agent_name"])
  print("=" * 72)
  print(f"Summary:         {result['editorial_summary']}")
  print(f"Readiness Score: {result['review']['readiness_score']}/100 ({result['review']['status']})")
  print(f"Brand Compliant: {result['style_check']['is_compliant']}")
  print("\nRun of Show:")
  for item in result["talking_points"]["run_of_show"]:
    print(f"  - {item}")
  print("=" * 72)
Jetski
expires: Oct 5 at 6:06 PM
20261001.01_p0 | 2
