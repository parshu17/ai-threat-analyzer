# modules/summarizer.py
from transformers import pipeline

SUM_MODEL = "sshleifer/distilbart-cnn-12-6"  # small-ish summarization model
_summarizer = None

def get_summarizer():
    global _summarizer
    if _summarizer is None:
        _summarizer = pipeline("summarization", model=SUM_MODEL, device=-1)  # device=-1 -> CPU
    return _summarizer

def summarize_text(text, max_length=60):
    if not text or len(text.strip())==0:
        return ""
    s = get_summarizer()
    try:
        out = s(text, max_length=max_length, min_length=20, do_sample=False)
        return out[0]["summary_text"]
    except Exception as e:
        return f"[summarize_error: {e}]"
