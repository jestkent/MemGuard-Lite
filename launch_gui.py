"""Windows executable entrypoint for MemGuard GUI."""

from memguard.main import main


if __name__ == "__main__":
    main(["--gui"])
