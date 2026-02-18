"""
Webhook Server (FastAPI)
─────────────────────────
FastAPI application that listens for GitHub webhook events
and triggers the code review pipeline on PR events.

Features:
  - Async request handling
  - Automatic OpenAPI documentation at /docs
  - Pydantic request/response models
  - HMAC webhook signature verification
"""

import hashlib
import hmac
import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import Optional

from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

from .review_agent import ReviewAgent, setup_logging

load_dotenv()

logger = logging.getLogger(__name__)

# ── Pydantic Models ───────────────────────────────────────────────────────


class ManualReviewRequest(BaseModel):
    """Request body for the manual review endpoint."""
    repo: str
    pr: int


class ReviewResponse(BaseModel):
    """Response body for review trigger endpoints."""
    message: str
    repo: str
    pr: int


class HealthResponse(BaseModel):
    """Response body for the health check endpoint."""
    status: str
    service: str


# ── App Lifespan & State ──────────────────────────────────────────────────

_review_agent: Optional[ReviewAgent] = None


def get_review_agent() -> ReviewAgent:
    """Return (and lazily initialise) the singleton ReviewAgent instance."""
    global _review_agent
    if _review_agent is None:
        _review_agent = ReviewAgent()
    return _review_agent


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise the review agent on startup."""
    setup_logging(os.getenv("LOG_LEVEL", "INFO"))
    logger.info("Code Review Agent webhook server starting up.")
    get_review_agent()
    yield
    logger.info("Webhook server shutting down.")


app = FastAPI(
    title="Code Review Agent",
    description=(
        "Intelligent automated code review system that integrates "
        "with GitHub pull request workflows."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# ── Webhook Signature Verification ───────────────────────────────────────

def verify_signature(payload_body: bytes, signature: str) -> bool:
    """Verify GitHub webhook HMAC-SHA256 signature."""
    secret = os.getenv("WEBHOOK_SECRET", "")
    if not secret:
        logger.warning("WEBHOOK_SECRET not set; skipping verification.")
        return True

    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"),
        payload_body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


# ── Background Task ──────────────────────────────────────────────────────

def run_review(repo: str, pr_number: int) -> None:
    """Run the review pipeline (executed as a background task)."""
    try:
        agent = get_review_agent()
        result = agent.review_pull_request(repo, pr_number)
        logger.info(
            "Review of %s#%d completed: %d issues found.",
            repo, pr_number, result["total_issues"],
        )
    except Exception as exc:
        logger.error("Review of %s#%d failed: %s", repo, pr_number, exc)


# ── Routes ────────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health():
    """Health check endpoint."""
    return HealthResponse(status="ok", service="code-review-agent")


@app.post("/webhook", tags=["GitHub"])
async def webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: Optional[str] = Header(None),
    x_github_event: Optional[str] = Header(None),
):
    """
    Handle GitHub webhook events.

    Configure your GitHub repo webhook to send `pull_request` events to this endpoint.
    The review pipeline runs asynchronously in the background.
    """
    body = await request.body()

    # Verify signature
    if not verify_signature(body, x_hub_signature_256 or ""):
        raise HTTPException(status_code=401, detail="Invalid webhook signature.")

    payload = await request.json()

    if x_github_event == "ping":
        logger.info("Received ping event.")
        return {"message": "pong"}

    if x_github_event == "pull_request":
        action = payload.get("action", "")
        if action in ("opened", "synchronize", "reopened"):
            repo = payload["repository"]["full_name"]
            pr_number = payload["pull_request"]["number"]

            # ── Prevent infinite loop ─────────────────────────────────
            # When the refactoring agent commits to the PR, GitHub fires
            # a "synchronize" event. Skip it to avoid re-triggering.
            if action == "synchronize":
                sender = payload.get("sender", {}).get("login", "")
                head_commit_msg = payload.get("pull_request", {}).get(
                    "head", {}
                ).get("label", "")

                # Check the latest commit on the PR via the API
                try:
                    agent = get_review_agent()
                    if agent.github_client:
                        pr_obj = agent.github_client.get_pull_request(repo, pr_number)
                        commits = list(pr_obj.get_commits())
                        if commits:
                            last_commit = commits[-1]
                            last_msg = last_commit.commit.message
                            if last_msg.startswith("refactor:") and "Refactoring Agent" in last_msg:
                                logger.info(
                                    "Skipping review for %s #%d — last commit is from the review agent.",
                                    repo, pr_number,
                                )
                                return {"message": "Skipped: agent-authored commit"}
                except Exception as exc:
                    logger.warning("Could not check last commit: %s", exc)

            logger.info(
                "PR event: %s #%d (%s) — scheduling review.",
                repo, pr_number, action,
            )

            background_tasks.add_task(run_review, repo, pr_number)

            return ReviewResponse(
                message="Review scheduled",
                repo=repo,
                pr=pr_number,
            )
        else:
            logger.debug("Ignoring PR action: %s", action)
            return {"message": f"Ignored action: {action}"}

    logger.debug("Ignoring event: %s", x_github_event)
    return {"message": f"Ignored event: {x_github_event}"}


@app.post(
    "/review",
    response_model=ReviewResponse,
    tags=["Manual"],
    summary="Trigger a review manually",
)
async def manual_review(
    body: ManualReviewRequest,
    background_tasks: BackgroundTasks,
):
    """
    Trigger a code review manually via API.

    Provide the GitHub `repo` (owner/repo) and `pr` number.
    The review runs asynchronously in the background.
    """
    background_tasks.add_task(run_review, body.repo, body.pr)
    return ReviewResponse(
        message="Review scheduled",
        repo=body.repo,
        pr=body.pr,
    )


# ── Entry Point ───────────────────────────────────────────────────────────

def main():
    """Start the FastAPI webhook server with uvicorn."""
    import uvicorn

    setup_logging(os.getenv("LOG_LEVEL", "INFO"))

    host = os.getenv("WEBHOOK_HOST", "0.0.0.0")
    port = int(os.getenv("WEBHOOK_PORT", "3000"))

    logger.info("Starting FastAPI webhook server on %s:%d", host, port)
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
