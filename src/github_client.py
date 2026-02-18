"""
GitHub API Client
─────────────────
Handles all interactions with the GitHub API:
  - Authentication via Personal Access Token
  - Fetching PR metadata, diffs, file contents, commit history
  - Posting line-level and summary review comments
  - Rate limit handling with exponential backoff
"""

import logging
import time
from typing import Optional

from github import Github, GithubException, RateLimitExceededException
from github.PullRequest import PullRequest
from github.Repository import Repository

logger = logging.getLogger(__name__)


class GitHubClient:
    """Wrapper around PyGithub for PR-focused operations."""

    def __init__(self, token: str, max_retries: int = 3):
        """Initialise the client with a GitHub PAT and retry configuration."""
        self.github = Github(token, retry=max_retries)
        self.max_retries = max_retries
        logger.info("GitHub client initialised successfully.")

    # ── Repository & PR Access ────────────────────────────────────────────

    def get_repo(self, repo_full_name: str) -> Repository:
        """Get a repository by full name (owner/repo)."""
        return self._with_retry(lambda: self.github.get_repo(repo_full_name))

    def get_pull_request(self, repo_full_name: str, pr_number: int) -> PullRequest:
        """Fetch a pull request by number."""
        repo = self.get_repo(repo_full_name)
        return self._with_retry(lambda: repo.get_pull(pr_number))

    # ── PR Data Retrieval ─────────────────────────────────────────────────

    def get_pr_metadata(self, pr: PullRequest) -> dict:
        """Extract key metadata from a PR."""
        return {
            "number": pr.number,
            "title": pr.title,
            "body": pr.body or "",
            "state": pr.state,
            "author": pr.user.login,
            "base_branch": pr.base.ref,
            "head_branch": pr.head.ref,
            "head_sha": pr.head.sha,
            "created_at": pr.created_at.isoformat(),
            "updated_at": pr.updated_at.isoformat(),
            "changed_files": pr.changed_files,
            "additions": pr.additions,
            "deletions": pr.deletions,
        }

    def get_pr_diff(self, pr: PullRequest) -> list[dict]:
        """Fetch all changed files in a PR with their patches."""
        files = self._with_retry(lambda: list(pr.get_files()))
        result = []
        for f in files:
            result.append({
                "filename": f.filename,
                "status": f.status,           # added, modified, removed, renamed
                "additions": f.additions,
                "deletions": f.deletions,
                "changes": f.changes,
                "patch": f.patch or "",
                "sha": f.sha,
                "previous_filename": f.previous_filename,
            })
        return result

    def get_file_content(self, repo: Repository, path: str, ref: str) -> Optional[str]:
        """Retrieve the full content of a file at a specific commit ref."""
        try:
            content_file = self._with_retry(
                lambda: repo.get_contents(path, ref=ref)
            )
            if isinstance(content_file, list):
                logger.warning("Path %s is a directory, not a file.", path)
                return None
            return content_file.decoded_content.decode("utf-8", errors="replace")
        except GithubException as exc:
            if exc.status == 404:
                logger.info("File %s not found at ref %s.", path, ref)
                return None
            raise

    def get_commit_history(self, pr: PullRequest) -> list[dict]:
        """Fetch commits in the PR."""
        commits = self._with_retry(lambda: list(pr.get_commits()))
        return [
            {
                "sha": c.sha,
                "message": c.commit.message,
                "author": c.commit.author.name,
                "date": c.commit.author.date.isoformat(),
            }
            for c in commits
        ]

    # ── Posting Review Comments ───────────────────────────────────────────

    def post_review_comments(
        self,
        pr: PullRequest,
        comments: list[dict],
        summary: str,
    ) -> None:
        """
        Post a full review with line-level comments and a summary body.

        Each comment dict must have:
          - path: str       (file path)
          - line: int       (absolute line number — used as fallback)
          - body: str       (markdown comment body)
          - side: str       (RIGHT for new code)
          - position: int   (optional — diff-relative position, preferred by GitHub)
        """
        if not comments and not summary:
            logger.info("No comments to post.")
            return

        # Post the review with inline comments
        try:
            review_comments = []
            for c in comments:
                comment_data = {
                    "path": c["path"],
                    "side": c.get("side", "RIGHT"),
                    "body": c["body"],
                }
                # GitHub's review API prefers 'position' (diff-relative).
                # Fall back to 'line' (absolute) if position not available.
                if "position" in c:
                    comment_data["position"] = c["position"]
                else:
                    comment_data["line"] = c["line"]
                review_comments.append(comment_data)

            self._with_retry(lambda: pr.create_review(
                body=summary,
                event="COMMENT",
                comments=review_comments,
            ))
            logger.info(
                "Posted review with %d inline comments.", len(review_comments)
            )
        except GithubException as exc:
            logger.error("Failed to post review: %s", exc)
            # Fallback: post as individual issue comments
            self._post_fallback_comments(pr, comments, summary)

    def post_summary_comment(self, pr: PullRequest, body: str) -> None:
        """Post a standalone issue comment (not tied to a line)."""
        self._with_retry(lambda: pr.create_issue_comment(body))
        logger.info("Posted summary comment on PR #%d.", pr.number)

    # ── Committing Changes (for refactoring agent) ────────────────────────

    def commit_file_change(
        self,
        repo: Repository,
        path: str,
        new_content: str,
        commit_message: str,
        branch: str,
    ) -> str:
        """Update a file on a branch and return the new commit SHA."""
        try:
            contents = self._with_retry(
                lambda: repo.get_contents(path, ref=branch)
            )
            result = self._with_retry(lambda: repo.update_file(
                path=path,
                message=commit_message,
                content=new_content,
                sha=contents.sha,
                branch=branch,
            ))
            sha = result["commit"].sha
            logger.info("Committed change to %s on %s (SHA: %s).", path, branch, sha)
            return sha
        except GithubException as exc:
            logger.error("Failed to commit change to %s: %s", path, exc)
            raise

    # ── Internal Helpers ──────────────────────────────────────────────────

    def _with_retry(self, func, retries: int = None):
        """Execute a GitHub API call with exponential backoff on rate limits."""
        retries = retries or self.max_retries
        for attempt in range(retries):
            try:
                return func()
            except RateLimitExceededException:
                reset_time = self.github.get_rate_limit().core.reset
                wait_seconds = max(
                    (reset_time - __import__("datetime").datetime.utcnow()).total_seconds(),
                    1,
                )
                logger.warning(
                    "Rate limited. Waiting %.0f seconds (attempt %d/%d).",
                    wait_seconds, attempt + 1, retries,
                )
                time.sleep(min(wait_seconds, 60))
            except GithubException as exc:
                if exc.status >= 500 and attempt < retries - 1:
                    wait = 2 ** attempt
                    logger.warning(
                        "Server error %d. Retrying in %ds.", exc.status, wait
                    )
                    time.sleep(wait)
                else:
                    raise
        raise RuntimeError("Max retries exceeded for GitHub API call.")

    def _post_fallback_comments(
        self, pr: PullRequest, comments: list[dict], summary: str
    ) -> None:
        """Fallback: post comments as individual issue comments."""
        if summary:
            self.post_summary_comment(pr, summary)
        for c in comments:
            body = f"**{c['path']}** (line {c['line']}):\n\n{c['body']}"
            self._with_retry(lambda b=body: pr.create_issue_comment(b))
        logger.info("Posted %d fallback comments.", len(comments))

    def check_connection(self) -> bool:
        """Verify the token works and log the authenticated user."""
        try:
            user = self.github.get_user()
            logger.info("Authenticated as: %s", user.login)
            return True
        except GithubException as exc:
            logger.error("Authentication failed: %s", exc)
            return False
