# Performance

How fast BlazeServe feels depends mostly on things outside it: your disk, your network, whether HTTPS or a proxy is involved, and your operating system. The only numbers that matter are the ones you measure on your own setup, and BlazeServe includes a tool for that.

## Quick measurement

```bash
blaze benchmark --json --size-mb 100
```

With no address, this starts a temporary server on your own machine, downloads from it, and shuts it down. To measure a server that already exists, pass its address with `--url`. In that case no extra server is started. A run that receives fewer bytes than expected counts as a failure, not as a result.

## Repeatable measurements

If you want to compare two versions or two settings, ask for several runs and save them:

```bash
blaze benchmark --runs 7 --warmup 2 --workload both --size-mb 512 --output run1.json
blaze benchmark --runs 7 --warmup 2 --workload both --size-mb 512 --output run2.json
blaze benchmark compare run1.json run2.json
```

| Option | Meaning |
| :--- | :--- |
| `--runs N` | How many measurements to record per workload |
| `--warmup N` | How many to throw away first (default 1) |
| `--workload` | `full` for whole files, `range` for partial requests, or `both` |
| `--output FILE` | Save the results, with the command, settings, test data seed and every sample |
| `--seed N` | Seed for the test data, so runs use identical content |

`compare` prints the middle value of each workload in both files and how much it changed. It does not tell you whether the difference is meaningful, so look at how much your runs vary before you draw a conclusion.

## Reference numbers

These were measured on one machine, over loopback only, with no HTTPS or proxy: an AMD Ryzen 5 5625U with 15 GB of RAM on Windows 11, a release build of 1.0.0, a 512 MiB test file, and 7 recorded samples after 2 warm-ups. Three separate runs gave:

| Run | Whole file (median) | Partial requests (median) |
| :--- | ---: | ---: |
| 1 | 1033 MiB/s | 1334 MiB/s |
| 2 | 1333 MiB/s | 1309 MiB/s |
| 3 | 1317 MiB/s | 1360 MiB/s |

Within a run the results varied by 8 to 15 percent of the median, and run 1 sits about 22 percent below the other two. Differences of that size are noise on this machine.

For comparison, the old Python server measured on the same machine with five single runs and no warm-up gave 616, 633, 677, 749 and 759 MiB/s, with a median of 677. The measuring methods differ, so read the roughly twofold gap as a hint, not an exact figure. Loopback also says little about a real network, where the link is usually the limit.

When you share a performance number, include the command, the version, the operating system, the CPU, the storage and the network path. A figure without those cannot be checked.

## Tuning on Linux

For busy servers, `deploy/linux-tuning/` has a script that checks and applies sensible network settings. See [deploy/README.md](../deploy/README.md#linux-tuning). Measure before and after, and change defaults only when the numbers justify it.
