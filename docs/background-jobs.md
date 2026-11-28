# Background jobs

Run a download, an upload or a server in the background, then check on it or stop it from any terminal.

```console
blaze get https://example.com/archive.tar -o archive.tar --background
blaze put backup.tar http://localhost:5949 --background
blaze serve ./shared --background
blaze send ./report.pdf --background
```

Each command prints a job ID, such as `3f9a01bc`, and returns. The work continues after you close the terminal.

```console
blaze status              # active jobs
blaze status 3f9a01bc     # one job, with its result and log
blaze status --watch      # keep refreshing; Ctrl+C only closes the viewer
blaze status --json       # one JSON snapshot for scripts
blaze stop 3f9a01bc       # show the job and ask before stopping it
```

## What a launch means

`--background` checks your options first. If the command cannot start, you get the error and a nonzero exit code, and no job is created. That covers a bad option, a missing password variable and a file that cannot be read.

`serve` and `send` print their job ID only after the server has bound its port. A port that is already in use, or a bad certificate, is reported to you with a nonzero exit code.

For `get` and `put`, a successful launch means the job has started. A network failure, a rejected upload or a checksum mismatch after that point is the job's result. Look for it with `blaze status ID`.

Relative paths are resolved from the folder where you ran the command, so you can run `status` and `stop` from anywhere. A background job never asks questions.

## What `blaze status` shows

Each job has an ID, a type (`get`, `put`, `serve` or `send`), a process ID, a state, a start time and the time of its last update.

| Field | Meaning |
| :--- | :--- |
| State | `starting`, `running`, `stopping`, `completed`, `failed`, `interrupted` or `stopped` |
| Phase | For transfers: `preparing`, `transferring`, `retrying` or `finalizing`. Finalizing covers the SHA-256 check and moving the finished file into place, and the last upload request |
| Progress | Bytes done and total, the percentage, the recent speed and the time left. Anything that cannot be known yet reads `unknown`, never `0` |

Names are shown without their folders, and a remote address shows only the scheme, host and port. A parallel download is one job. Bytes you already had from an earlier attempt count towards completion but not towards the speed, and retried bytes are never counted twice.

A server job shows what it serves, the address it listens on and how long it has been up. It does not list the people connected to it. For that, use [Monitoring](monitoring.md).

`blaze status` shows active jobs. `--all` adds finished ones that are still kept, and `blaze status ID` shows any kept job, including its final result and the location of its log.

## Stopping a job

`blaze stop ID` shows the job and its progress, then asks for confirmation. Without a terminal, or in a script, add `--yes`.

- A transfer closes its files and connections and ends as `interrupted`. The partial file and its resume data stay, so running the same `blaze get` or `blaze put` again carries on.
- A server shuts down gracefully, finishing the requests in flight, and ends as `stopped`.
- A job that does not wind down within 10 seconds records its result and ends anyway.
- Stopping a job that already finished reports how it ended and changes nothing.

`blaze stop` never signals a process by its number. It leaves a request for the job's own worker, which is the only process that can act on it. A process that reused the number of a finished job is never touched. An unknown or expired ID is an error.

## How long records are kept

Finished jobs stay for 24 hours after their last update, and at most 100 are kept, oldest removed first. Their logs go with them. Cleanup runs whenever you start a background job or run `blaze status`.

A job that is still marked as running, but whose worker has not updated its record for 30 seconds, is shown as `failed` with a note that it stopped responding. This is what a crash, a kill or a reboot looks like. The next cleanup removes it once it is old enough.

## Where the records are

Records and logs live in a private folder for your user.

| System | Folder |
| :--- | :--- |
| Windows | `%LOCALAPPDATA%\blazeserve\jobs` |
| macOS | `~/Library/Application Support/blazeserve/jobs` |
| Linux | `$XDG_STATE_HOME/blazeserve/jobs`, or `~/.local/state/blazeserve/jobs` |

Set `BLAZE_STATE_DIR` to use `<that folder>/jobs` instead. On Linux and macOS the folder is mode `0700` and each file `0600`. On Windows the folder inherits the permissions of your user profile, which other standard users cannot read.

A record holds the ID, type, process ID, state, times, progress, a short file or folder name and the sanitized result. It never holds a password, an `Authorization` header, an `--auth-env` value, the user name, query string or fragment of a URL, or the full path of a file. Control characters in names and error text are escaped. A problem writing a record never interrupts the transfer itself.

Passwords given on the command line with `--auth` are visible in the process list of a running job, exactly as they are for a foreground command. Prefer `--auth-env`.

## Limits

- Jobs are not restarted after a crash, and do not start at boot or return after a reboot.
- Closing the terminal does not end a job. Logging out can, depending on the system. On Windows, signing out ends your processes. On Linux, a systemd user session may stop them at logout unless lingering is enabled (`loginctl enable-linger`). A sleeping computer pauses a job; it carries on at wake, and the connection may need a retry.
- A job whose clock or computer sleeps for more than 30 seconds can briefly show as `failed`. It corrects itself at its next update.
- `--background` needs the `blaze` program. It is not available when BlazeServe is called as a Python library.
- There is no queue, no pause and no web page. `--json` and `--watch` cannot be combined.
