"""
Voice agent — HIPAA mode scrubs PHI from transcripts before LLM.
"""
from sentinel import scrub, rehydrate
from chronicle import Logger

log = Logger(log_path="./logs/voice-audit.log")


def process_transcript(session_id: str, transcript: str) -> str:
    """Scrub PHI from transcript, call LLM, restore for display/TTS."""
    clean, vault = scrub(transcript, mode="hipaa")

    with log.trace(session_id, "voice_llm_call") as trace:
        trace.record_input(clean)
        # Replace with real LLM call
        response = f"[LLM response based on clean transcript]"
        trace.record_output(response)

    return rehydrate(response, vault)


if __name__ == "__main__":
    transcript = "Patient John Smith, DOB 1985-03-15, MRN: ABC123456, called about prescription."
    result = process_transcript("session-001", transcript)
    print(result)
