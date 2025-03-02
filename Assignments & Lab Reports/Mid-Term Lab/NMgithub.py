import os
import git
from pathlib import Path


def push_changes(repo_path=None):
    """
    Pushes changes to the remote Git repository only if there are uncommitted changes.

    :param repo_path: Path to the local Git repository.
    """
    try:
        # Set the repo path, default to the current working directory
        repo_path = Path(repo_path or Path.cwd().parents[1])

        if not (repo_path / ".git").exists():
            raise ValueError(f"Not a valid Git repository: {repo_path}")

        repo = git.Repo(repo_path)

        # Check if there are any changes
        if repo.is_dirty(untracked_files=True):
            print("There are changes. Committing and pushing...")
            repo.git.add(update=True)
            repo.index.commit("Pushing updates on GitHub via NMgithub.py")

            # Push to the remote repository
            repo.remote('origin').push()
            print("Changes pushed successfully.")
        else:
            print("No changes to commit.")

    except git.exc.InvalidGitRepositoryError:
        print(f"Error: The directory '{repo_path}' is not a valid Git repository.")
    except git.exc.GitCommandError as git_error:
        print(f"Git error: {git_error}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":

    push_changes()
