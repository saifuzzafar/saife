"""
SAIFE Test Targets
==================
Three FastAPI chatbots with different security levels.
Used to test and validate the scanner agent.

- vulnerable_chatbot.py  → No protections (score < 30)
- partial_chatbot.py     → Basic filtering (score 50-70)
- secure_chatbot.py      → Properly hardened (score > 80)

Run individually:
    uvicorn target.vulnerable_chatbot:app --port 9001
    uvicorn target.partial_chatbot:app --port 9002
    uvicorn target.secure_chatbot:app --port 9003
"""
