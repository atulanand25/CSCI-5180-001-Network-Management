import os
import git
from pathlib import Path


def push_changes(repo_path=None):
    """
    Pushes changes to the remote Git repository.

    :param repo_path: Path to the local Git repository.
    """
    try:
        repo_path = repo_path or Path.cwd().parents[1]

        if not os.path.isdir(os.path.join(repo_path, ".git")):
            raise ValueError(f"Not a valid Git repository: {repo_path}")

        repo = git.Repo(repo_path)
        repo.git.add(update=True)
        repo.index.commit("pushing updates on  GitHub via NMgithub.py")
        repo.remote('origin').push()
        print("Changes pushed successfully.")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":

    push_changes()
