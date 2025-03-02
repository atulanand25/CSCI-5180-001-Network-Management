import git
from pathlib import Path


def push_changes(repo_path=None):
    """
    Compares modified files in the local repository against the GitHub repository.
    Then, pushes if there are any local changes.

    :param repo_path: Path to the local Git repository.
    """
    try:
        # Set the repo path, default to the current working directory
        repo_path = Path(repo_path or Path.cwd().parents[1])

        if not (repo_path / ".git").exists():
            raise ValueError(f"Not a valid Git repository: {repo_path}")

        repo = git.Repo(repo_path)

        # Fetch the latest changes from the remote repository
        repo.remote('origin').fetch()

        # Compare local repository with the remote repository
        local_commit = repo.head.commit
        remote_commit = repo.commit('origin/main')  # Assumes you're working with the 'main' branch
        # Check for changes in the working directory compared to the last commit
        changes_in_tracked_files = repo.index.diff("HEAD")

        # Check for untracked files
        untracked_files = repo.untracked_files

        # Check if there are any changes between the local and remote repositories
        if local_commit != remote_commit:
            # Check for changes in tracked files
            changes_in_tracked_files = repo.index.diff("HEAD")

            # Check for untracked files
            untracked_files = repo.untracked_files

            # If there are any changes, commit and push
            if changes_in_tracked_files or untracked_files:
                print("There are changes. Committing and pushing...")
                repo.git.add(update=True)  # Stage modified files
                repo.index.commit("pushing updates on GitHub via NMgithub.py")  # Commit changes
                repo.remote('origin').push()  # Push changes to the remote repository
                print("Changes pushed successfully.")
            else:
                print("No local changes detected. Skipping push.")
        else:
            print("Local repository is up to date with the remote.")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":

    push_changes()
