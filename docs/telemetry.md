# Telemetry

BlazeServe sends anonymous usage analytics by default, so the project can see which commands and options are used, where people get stuck and what breaks. This page lists everything that is sent, how to turn it off and what happens to it.

## Turn it off

Any one of these is enough:

- run `blaze telemetry disable`
- set the environment variable `BLAZE_TELEMETRY=0`
- set `DO_NOT_TRACK=1`

It is also off whenever the `CI` environment variable is set, and in builds without a project key, such as ones you compile yourself. The first time it would send anything, BlazeServe prints a notice to standard error. Nothing is sent before that notice has been shown: a piped or background command stays silent until you have seen it.

## Check what it does

| Command | What it does |
| :--- | :--- |
| `blaze telemetry status` | Whether analytics are on, why not, your anonymous ID and any events waiting |
| `blaze telemetry preview` | Prints example events. Nothing is sent |
| `blaze telemetry enable` / `disable` | Saves your choice. `disable` also discards events waiting to be sent |
| `blaze telemetry reset` | Removes your choice and the anonymous ID. The notice shows again |

Set `BLAZE_TELEMETRY_DEBUG=1` to print each event instead of sending it.

## What is sent

| When | Event |
| :--- | :--- |
| A command ends | The command, the names of the options given (never their values), whether it succeeded, the exit code, a fixed word for the kind of error, how long it took |
| A transfer | Also timings of each phase, a size range, the number of connections, whether it resumed, throughput |
| `serve` or `send` starts, every hour, and stops | Which features are on (yes or no) and the server's counters: uptime, requests, bytes sent and received, errors and refused connections. Totals only, nothing per visitor |
| You read help, or a command line is refused | The command and a fixed word for what was wrong, to find confusing parts |
| BlazeServe crashes (analytics on) | The place in the source code that crashed. Not the error message |
| You answer the rating question | The stars and any comment. After a successful transfer at a terminal, BlazeServe asks now and then; once you answer it never asks again, and after three skips it stops |
| BlazeServe crashes and you agree to report it | Where it crashed, the redacted message and the run log. Asked at once at a terminal, or at your next run there |
| You run `blaze bug` | What you typed, and the run log if you attach it, shown to you and confirmed before it is sent |

Every event carries: a random install ID, a random ID for that run, the BlazeServe version, how it was installed, the operating system and release, CPU architecture and count, memory and disk size ranges, language, terminal, shell, whether it runs in a container, WSL, SSH or Python, and whether a person is at the terminal.

PostHog receives the connection's IP address, derives an approximate location (country, region, city) from it, and discards the address.

## Run logs on your machine

Each command leaves a short log in the `logs` folder of the BlazeServe configuration folder: the command, option names, exit code, error message and progress notes, with URLs, paths, file names, addresses and e-mail addresses replaced. The last 20 are kept. Nothing is sent from them unless you attach one with `blaze bug`. Set `BLAZE_RUN_LOG=0` to turn them off.

## What is never sent

`blaze bug` sends only what you confirm, plus the machine details above. It works even with analytics off, and then uses a one-off ID. The rating question is not asked when analytics are off.

File names, paths, URLs, host names, ports, addresses of your visitors, anything from a request, passwords, option values, the values of environment variables, file contents and error messages. `blaze upgrade`, `blaze telemetry`, `blaze completions` and `blaze man` report nothing. Nothing is added to the pages BlazeServe serves: there is no tracking of the people who visit your server.

## Where it goes and your data

Events go to [PostHog](https://posthog.com) Cloud in the European Union, over HTTPS, with a write-only project key. PostHog processes them for the BlazeServe maintainer and keeps them for the project's retention period. They are used only to improve BlazeServe, and are not sold or combined with other data.

The install ID is random and identifies nothing about you, but it does link your events together. To have your data deleted, send the ID shown by `blaze telemetry status` to the address in [SECURITY.md](../SECURITY.md), then run `blaze telemetry reset`.

Your settings are in `telemetry.json` in the BlazeServe configuration folder, which `blaze telemetry status` prints. Events of quick commands wait in `telemetry-queue.jsonl` beside it and go out with the next longer command, at most 50 of them.

## Servers and containers

A container or service prints the notice into its log the first time. Because its settings are lost when the container is replaced, turn analytics off with `BLAZE_TELEMETRY=0` in its environment.

## Building from source

Set `BLAZE_POSTHOG_KEY` to a PostHog project key (`phc_...`) when building to send to your own project, and `BLAZE_POSTHOG_HOST` for another region or a self-hosted PostHog. The same variables override a built-in key at run time. Keys that are not project keys are refused.
