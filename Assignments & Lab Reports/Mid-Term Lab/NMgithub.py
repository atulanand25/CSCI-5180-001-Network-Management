import git
from pathlib import Path


def push_changes(repo_path=None):
    """
    Compares modified files in the local repository against the last commit.
    Commits if there are changes and pushes the changes to the remote repository
    if the local commit is ahead of the remote commit.

    :param repo_path: Path to the local Git repository.
    """
    try:
        # Use current working directory if no repo path is provided
        repo_path = repo_path or Path.cwd().parents[1]
        repo = git.Repo(repo_path)


        # Check for changes in tracked files compared to the last commit
        changes_in_tracked_files = repo.git.diff("HEAD")

        if changes_in_tracked_files:
            print("There are changes in tracked files. Committing changes...")
            repo.git.add(update=True)  # Stage modified files
            repo.index.commit("pushing updates on GitHub via NMgithub.py")  # Commit changes
            print("Local changes committed.")
        else:
            print("No changes detected in tracked files. Skipping commit.")
            return  # No changes to push, exit early

        # Fetch the latest changes from the remote repository
        repo.remote('origin').fetch()

        # Check if local HEAD is ahead of the remote (origin/main)
        local_commit = repo.head.commit
        remote_commit = repo.commit('origin/main')

        if local_commit != remote_commit:
            print("Local commit is ahead of remote. Pushing changes...")
            repo.remote('origin').push()  # Push changes to the remote repository
            print("Changes pushed to remote repository.")
        else:
            print("Local commit matches remote. No need to push.")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":

    push_changes()
