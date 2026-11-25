# Component interfaces

This document fixes the interfaces between Sieve's components, so each of us can build one side without waiting for the other. The finding format itself is in docs/finding-format.md.

- Plug-in contract: how the scan service runs an analyzer.
- Triage API: what the triage agent reads and writes.
- Report schema: what the report service produces from an approved finding.

## Plug-in contract

A plug-in is one analyzer packed as a Docker image, plus a manifest that tells the scan service how to run it. The plug-in reads the code from /src and writes SARIF 2.1.0 to /out. That is all the core knows about it, so adding an analyzer means adding a plug-in and its adapter, and nothing in the core changes (requirements F1 and N5). The plug-in runner (T2.1) is the host side of this contract.

### Plug-in directory

Each plug-in has its own directory in the repository:

    plugins/semgrep/
      plugin.toml    the manifest
      Dockerfile     installs the tool and its rules at pinned versions
      run.sh         the entry point: runs the tool, writes the SARIF file, maps exit codes

The adapter that turns the plug-in's SARIF into findings lives in the back end (T2.2), and the manifest names it. The adapter named `x` is the class in `backend/app/adapters/x.py` whose `tool` is `x`, so a new adapter adds only its own module and tests.

### Manifest

The manifest is TOML, so the back end reads it with Python's `tomllib` and needs no extra library.

```toml
name = "semgrep"
image = "sieve-plugin-semgrep:1.183.0-16b9e6d"
languages = ["python", "java", "javascript", "typescript"]
adapter = "semgrep"
timeout_seconds = 600

[versions]
tool = "1.183.0"
rules = "semgrep-rules@16b9e6d45f10649f6a531ec4838ed9924372c3bc"
```

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | the plug-in's ID, lowercase. Findings store it in their `tool` field. |
| `image` | yes | the image to run. Its tag includes the tool and rules versions, so updating either means building a new image on purpose. |
| `languages` | yes | the languages it scans, or `["*"]` for a plug-in that scans every file, such as Gitleaks. The scan service skips a plug-in when the repository has no files in these languages. |
| `adapter` | yes | the adapter that reads its SARIF (docs/finding-format.md) |
| `timeout_seconds` | no | the time limit for the whole run, build step included. Default 600, at most 3600. |
| `versions.tool`, `versions.rules` | yes | recorded with every run. `versions.rules` is the rules repository and commit, or the plug-in that brings the rules. |
| `build.image` | no | an image for a build step that runs before the scan, for the Java plug-in |

The Java plug-in adds a build step and a longer time limit:

```toml
name = "spotbugs"
image = "sieve-plugin-spotbugs:4.10.5-fsb1.14.0"
languages = ["java"]
adapter = "spotbugs"
timeout_seconds = 1800

[versions]
tool = "4.10.5"
rules = "find-sec-bugs 1.14.0"

[build]
image = "sieve-plugin-spotbugs-build:jdk25-3.9.16"
```

### What the scan container gets

| Path | Access | Contents |
|---|---|---|
| `/src` | read-only | the files of the scanned commit, exported with `git archive` (see below) |
| `/out` | read and write, empty at start | where the plug-in writes `results.sarif` and `scan-info.json` |
| `/build` | read-only | the build step's output, only for plug-ins with a build step |
| `/tmp` | read and write, in memory | scratch space. `HOME` points here, because tools such as Semgrep write a cache to the home directory. |

The export in /src has no .git folder, so tools scan the same files whatever their Git settings, and no tool sees the repository's history. The export also leaves out two kinds of files:

- Everything that is not a regular file or a folder, such as symbolic links. A link in a scanned repository could point anywhere, for example to `/proc/self/environ`, and anything that reads the checkout later, inside the worker, would read the worker's environment, including the LLM API keys. We checked that `git archive` keeps such links.
- The tools' own ignore and configuration files: `.semgrepignore`, `.gitleaks.toml`, `.gitleaksignore` and `.bandit`. The scanned repository is not ours, so it must not decide what is scanned.

The runner starts every scan container like this:

    docker run --network none --read-only --tmpfs /tmp
      --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges
      --memory 4g --cpus 2 --pids-limit 512
      --label sieve.scan_id=<scan ID> --label sieve.run_id=<run ID> --label sieve.step=scan
      --mount <checkout>:/src,readonly --mount <run output>:/out
      -e SIEVE_SRC=/src -e SIEVE_OUT=/out -e HOME=/tmp
      <image>

- No network, so the container can't send code or findings anywhere (requirement N4), and the same image gives the same results on the same commit.
- Only the variables above are passed. The container never sees API keys or the host's environment.
- The labels let the worker find and remove containers left behind if it crashes in the middle of a scan.
- The memory, CPU and process limits are defaults in the back end's settings, not in the manifest.
- Before it starts the container, the worker creates the run's output folder and gives it to user 10001.

We tested these flags with Semgrep 1.183.0 on PyGoat: the scan works with no network, a read-only root file system, a non-root user and all capabilities dropped.

### Suppression in the scanned code

Each plug-in turns off the ways the scanned code can switch off its own findings, where the tool allows it: Semgrep runs with `--disable-nosem`, Bandit with `--ignore-nosec`, ESLint with `--no-inline-config` and our own configuration file, and Gitleaks with `--ignore-gitleaks-allow`. When a tool has no such option, the adapter still keeps the suppressed results and marks them (docs/finding-format.md).

We tested this with Semgrep 1.183.0. A `# nosemgrep` comment removed the finding from Semgrep's JSON output and marked it as suppressed in SARIF. With `--disable-nosem` it was reported normally. A `.semgrepignore` file in /src made Semgrep skip the file it named, even with that flag, which is why the export leaves such files out.

SpotBugs is the one tool where in-source suppression works: the scanned code can hide a SpotBugs finding with `@SuppressFBWarnings`. SpotBugs drops such results before it writes SARIF and has no option to keep them, and `-omitVisitors NoteSuppressedWarnings` doesn't stop it, so the adapter never sees them and can't mark them. Semgrep's Java rules still scan the same code.

### Build step

SpotBugs analyzes compiled classes, so the Java plug-in builds the project first, in its own container, before the scan container starts. The runner starts it like this:

    docker run --network sieve-build --read-only --tmpfs /tmp
      --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges
      --memory 4g --cpus 2 --pids-limit 1024
      --label sieve.scan_id=<scan ID> --label sieve.run_id=<run ID> --label sieve.step=build
      --mount <checkout>:/src,readonly --mount <run build folder>:/build
      --mount m2-<repository key>:/cache/m2
      -e SIEVE_SRC=/src -e SIEVE_BUILD=/build -e HOME=/tmp
      <build image>

The build image's entry point:

1. copies /src to /build/work, because Maven writes into the project folder
2. runs Maven 3.9.16 once in /build/work, with the image's Maven settings and `/cache/m2` as Maven's local repository: `mvn -B -DskipTests package org.apache.maven.plugins:maven-dependency-plugin:3.11.0:copy-dependencies -DincludeScope=compile -DoutputDirectory=/build/deps`. `package` builds the app, and `copy-dependencies` copies the libraries it is compiled against, including `provided` ones such as the servlet API. Both run in one Maven run because in a project with several modules, a module can depend on another module of the same project, and Maven finds that module only when it was packaged earlier in the same run.
3. writes `/build/java-build.json` with the app's own class folders (`target/classes` of each module) and source folders (`src/main/java` of each module), as paths relative to the repository root

If Maven exits with anything but 0, the run fails with the reason `build_failed`, and Semgrep still covers the Java code.

The scan container then gets /build read-only. Its entry point runs SpotBugs with Find Security Bugs on the class folders listed in `java-build.json` only, with the libraries in /build/deps as `-auxclasspath` and the source folders under /src as `-sourcepath`. Scanning all of /build/work would also analyze every library: in a test with a small Spring app, 2,438 of 2,456 results came from library code. With the source folders under /src, SpotBugs writes file paths the adapter can map (docs/finding-format.md). `files_scanned` is the number of class files analyzed. It reports the `SECURITY` category without `SPRING_ENDPOINT`, which lists Spring endpoints rather than bugs: 236 of the 455 results on WebGoat v2026.5.

Folders and owners:

- The worker creates `runs/<run ID>/build` and `runs/<run ID>/out` in the `sieve-data` volume and gives them to user 10001 before the build starts.
- The Maven cache is one volume per repository, named `m2-` plus the first 16 hex characters of the SHA-256 hash of the normalized repository URL. The build image creates /cache/m2 owned by user 10001, and Docker copies that owner into a new, empty volume the first time it is mounted, so the build can write to it without other setup. We tested this on Docker Desktop 29. One volume per repository means that one project's build can't plant files in a cache that another project's build later uses.

Network:

- `sieve-build` is an internal Docker network, with no route out. Compose creates it with `com.docker.network.bridge.inhibit_ipv4`, so its bridge has no address of the host. On an internal network without that option, the gateway address belongs to the host, and we saw a container on it connect to a listener in the engine's host network namespace through that address, on Docker Desktop with Engine 29.8 and on the Ubuntu runner in CI. On Linux that is the researcher's machine. The runner refuses to start a build on a network that isn't internal or whose bridge has an address. The build container's only neighbour on it is `maven-proxy`, a small forward proxy that is also on the `egress` network and allows only tunnels to Maven Central's host name (`repo.maven.apache.org`, port 443).
- `maven-proxy` is Squid 6.14, from Canonical's `ubuntu/squid` image for Ubuntu 24.04, pinned by digest in `maven-proxy/Dockerfile`. The image's tag says 6.6, the version Ubuntu 24.04 started with, but `squid -v` in it prints 6.14. Its configuration, `maven-proxy/squid.conf`, allows one thing: a `CONNECT` tunnel to `repo.maven.apache.org` on port 443. It refuses every other host, every other port, a host given as an IP address and plain HTTP requests, with 403, before it opens any connection. We chose Squid because its access rules can match the method, the host name and the port together, and because a maintained image of it exists that we only configure, not build. Squid matches the host name of the `CONNECT` request. It can't see inside the TLS connection.
- `repo.maven.apache.org` is served by Cloudflare, so a build can open the tunnel and then send another TLS server name, and reach any site hosted on Cloudflare. Through the tunnel, `curl --connect-to www.cloudflare.com:443:repo.maven.apache.org:443 https://www.cloudflare.com/` got 200 with www.cloudflare.com's own certificate. We accept this: a build only gets public code (requirement F2), and Maven Central already serves whatever anyone publishes to it. Checking the TLS server name with Squid's SslBump peek and splice would close it, but that needs a Squid built with OpenSSL, and Ubuntu's is built with GnuTLS.
- The proxy keeps no cache and writes no files. It runs as Squid's `proxy` user with a read-only root, no capabilities and `no-new-privileges`, and logs each request to its container's output. The two folders the image declares as volumes, `/var/log/squid` and `/var/spool/squid`, are tmpfs mounts, so a start leaves no anonymous volumes.
- The build image's Maven settings send every download through a mirror of Maven Central and through that proxy, so repositories that the project's pom.xml declares are not used.
- On Docker Desktop, a container on an ordinary bridge network could reach the internet and the host's published ports, including Sieve's API port. On `sieve-build` it reaches neither, which the test below checks.
- `test_runner_docker.py` checks this through the runner's build step, with `maven-proxy` started the way Compose starts it. From the build container, names outside the network don't resolve, a direct connection to an outside address fails, and the proxy answers 403 to `example.com`, to `host.docker.internal`, to an IP address, to Maven Central on ports 80 and 22, and to a plain HTTP request. A `CONNECT` to `repo.maven.apache.org:443` gets 200. A second test starts a listener in the engine's host network namespace and checks that the build container can't connect to it, neither through the build network's would-be gateway address nor through the gateway address of an internal network made without `inhibit_ipv4`, while a container on that other network can. We ran both on Docker Desktop with Engine 29.8, and CI runs them on its Ubuntu runner.

The trade-off: a Maven build runs code from the scanned project, such as plug-ins named in its pom.xml. That code can reach its own build folder, its own repository's cache and the tunnel to `repo.maven.apache.org`, which leads to Maven Central or, with another TLS server name, to other sites on Cloudflare. It can't reach Sieve's API, the database, other containers, the researcher's network or hosts outside Cloudflare, and it stops at the time limit. It could still change its own compiled classes, and so its own SpotBugs results, which affects only the scan of that same project. Requirement N4 lists the build step as its one exception to "no network".

### Results

The plug-in writes `/out/results.sarif`:

- SARIF 2.1.0 with one run. A scan that finds nothing still writes the file, with an empty `results` list.
- File paths relative to the repository root, or absolute under /src. The adapter turns both into paths relative to the repository root (docs/finding-format.md).
- At most 100 MB.

It also writes `/out/scan-info.json` with the number of files the tool scanned. A plug-in that scans every file, such as Gitleaks, reports the number of files in /src.

```json
{"files_scanned": 446}
```

A scan that scans nothing reports success with no findings, which looks exactly like a scan of clean code. We saw this happen while testing: when /src was mounted from the wrong folder, Semgrep scanned 0 files and exited with 0. So the runner checks the count (see Run statuses).

Other files the plug-in writes to /out are kept with the run for debugging, but nothing in Sieve reads them.

The Gitleaks plug-in runs Gitleaks with `--redact`, so its SARIF file doesn't contain the secret values. The adapter also masks the lines Gitleaks flagged (docs/finding-format.md). The plug-in passes `--config` with its own file, which holds only `[extend]` and `useDefault = true`: without `--config`, Gitleaks 8.30.1 takes its rules and allowlists from a `.gitleaks.toml` in the folder it scans. Gitleaks always obeys a `.gitleaksignore` in that folder, and no flag turns it off, so the plug-in exits with 1 when /src has one, and the run fails with `exit_code`. We tested both with a fake key: a `.gitleaks.toml` that allowed every path, or a `.gitleaksignore` that listed the finding, hid it without these checks.

### Exit codes

| Code | Meaning | Run status |
|---|---|---|
| 0 | the analyzer finished and wrote `results.sarif` | `succeeded` if the checks below pass |
| 3 | nothing to scan: no files the analyzer supports | `skipped` if the checkout really has no files in the plug-in's languages |
| any other | the analyzer failed | `failed` |

Tools use their own exit codes. Bandit, for example, exits with 1 when it finds issues. `run.sh` maps them to the codes above.

### Run statuses

A plug-in run goes through `pending`, then `building` for plug-ins with a build step, then `running`, and ends in one of these:

| Status | When | Reason recorded |
|---|---|---|
| `succeeded` | exit code 0, a valid SARIF file, and `files_scanned` above 0 when the checkout has files in the plug-in's languages | |
| `skipped` | exit code 3, and the checkout has no files in the plug-in's languages | |
| `failed` | exit code other than 0 or 3 | `exit_code` |
| `failed` | `results.sarif` or `scan-info.json` is missing | `missing_sarif` |
| `failed` | `files_scanned` is 0, or the exit code is 3, while the checkout has files in the plug-in's languages | `nothing_scanned` |
| `failed` | the file is not JSON, its version is not 2.1.0, it fails the SARIF 2.1.0 JSON schema, or it is larger than 100 MB | `invalid_sarif` |
| `failed` | the container ran out of memory | `out_of_memory` |
| `failed` | the build step failed | `build_failed` |
| `failed` | the image is missing, Docker can't be reached, or the container can't be created or started | `runner_error` |
| `failed` | the worker stopped during the run. Set when the worker starts again. | `interrupted` |
| `timed_out` | the run reached its time limit. The runner kills and removes the container. | |

The runner counts the files in the plug-in's languages itself. It leaves out files under folders named `node_modules`, which ESLint and Semgrep skip by default, so a checkout whose only JavaScript is in `node_modules` ends as `skipped` for the ESLint plug-in, not `failed`.

A plug-in that tries to reach the network can't: its container has only a loopback interface, so every connection fails at once. The runner's test plug-in for this case tries to connect, then exits with 1, so its run ends as `failed` with `exit_code`. The test also checks that a listener on the host received nothing.

One plug-in failing doesn't stop the others. When all of a scan's plug-in runs have ended, the scan gets the first of these statuses that applies:

1. `failed`, if no run succeeded and at least one failed or timed out
2. `partial`, if at least one run failed or timed out
3. `completed`, in every other case, including when every run was skipped

A scan whose clone or export fails is `failed` before any plug-in runs, and the error is recorded with the scan.

### Time limits

The default limit is 10 minutes for a whole run, build step included, and the Java plug-in sets 30 minutes. The scan step gets whatever time the build step left. We will check these limits against the real times of the baseline run in week 4.

### Logs and recorded versions

The runner saves the containers' standard output and error as the run's log, first the build step's and then the scan step's, up to 5 MB in total, for every run, including failed ones. After the run, the adapter adds its warnings and the number of results it dropped to the same log.

Each run records the plug-in, the image name and digest, the tool and rules versions from the manifest, the status and reason, the exit code, the start and end times, the number of files scanned, of results and of dropped results, and the paths of its SARIF file and log (`analyzer_runs` in docs/database.md).

The tool version that counts is the one in the manifest. The runner logs the version written in the SARIF file next to it, but doesn't compare them, because tools fill that field unreliably: Gitleaks 8.30.1 always writes `v8.0.0`, and SpotBugs and the ESLint formatter fill only `version`, not `semanticVersion`.

Rule versions stay fixed from the baseline run in week 4 to the final evaluation in week 9, so results can be compared. Updating rules means building a new image. The plug-in's command counts as part of its version too: Semgrep builds rule IDs from the paths it loads rules from, so changing how `run.sh` passes `--config` changes every rule ID, and with it every fingerprint.

### Example: the Semgrep plug-in

The image has Semgrep 1.183.0 and the semgrep-rules repository at a pinned commit in /opt/semgrep-rules. It runs only the security rules, because the other rules are about code style and correctness, not vulnerabilities. With the full Python rule set, 77 of the 227 results on PyGoat came from non-security rules.

```sh
#!/bin/sh
# Entry point of the Semgrep plug-in.
cd /opt/semgrep-rules || exit 1
configs=$(find python java javascript typescript -type d -name security \
  | sort | sed 's/^/--config /')
# Semgrep exits with 0 when the scan finished, with or without findings.
semgrep scan $configs --metrics off --disable-version-check --no-git-ignore \
  --disable-nosem \
  --sarif-output "$SIEVE_OUT/results.sarif" \
  --json-output /tmp/semgrep.json "$SIEVE_SRC" || exit 1
# Semgrep's JSON output lists the scanned files, its SARIF output doesn't.
python3 -c 'import json, sys
d = json.load(open("/tmp/semgrep.json"))
json.dump({"files_scanned": len(d["paths"]["scanned"])}, sys.stdout)' \
  > "$SIEVE_OUT/scan-info.json" || exit 1
```

We ran this script on three versions of PyGoat as user 10001, with no network and all capabilities dropped.

The rules are referenced with paths relative to /opt/semgrep-rules, because Semgrep builds rule IDs from those paths. This gives IDs such as `python.lang.security.audit.formatted-sql-query`, the same as in the Semgrep registry.

## Triage API

The triage agent takes the findings of one scan from the findings store, groups duplicates, checks each finding or group for false positives, scores its severity, and writes the results back. It reaches LLMs only through the provider interface (docs/class-diagrams.md), so every call is cached, counted against the run's budget and logged.

### Entry point

    triage_scan(scan_id, budget_usd, models) -> TriageRun

`models` names a cheaper and a stronger model. Each finding goes to the cheaper model first, and only the findings it is unsure about go to the stronger one.

A TriageRun records the scan, the models, the budget, the cost so far and a status: `running`, `finished` or `stopped_at_budget`. When the budget runs out, the run stops. Findings that were already triaged keep their results, and the rest stay untriaged, so a new run picks them up.

### Steps

| Step | Input | Output |
|---|---|---|
| Group | the scan's findings | duplicate groups, each with a record of how it was formed |
| Check | one triage item | a verdict |
| Score | one triage item and its verdict | a severity |

A triage item is one finding, or one duplicate group with its member findings. A group is checked and scored once, and the result applies to all of its members.

The group step is `group_scan()` in `backend/app/dedup/store.py`. It groups a scan once, after the scan has ended as `completed` or `partial`. It runs a list of steps in order, each a `GroupingStep` that gets the scan's findings and the groups so far and returns the groups after its own work: the rules first (`RuleStep`), then text similarity, then the LLM for the groups the rules leave unclear. The rules ask a `FunctionLookup` for the enclosing function of each finding, `enclosing_function(file, line)`, which returns the function's name and lines, or nothing. Without it they group by the same file and nearby lines only. Two findings of the same tool are grouped only when their lines overlap, because a tool reports each place it matched as its own result: two Semgrep rules on one call are one group, one rule on two forms is two findings.

The lookup Sieve uses is `TreeSitterFunctionLookup` in `backend/app/context/functions.py`, which also finds `context.function` below. It parses Python, Java, JavaScript and TypeScript files of the checkout with tree-sitter, reading them through `CheckoutReader`, and returns the innermost function that contains the line. A function is a function, method or constructor, named or not, or a lambda or arrow function whose body is a block. Its decorators and annotations are part of it, so a finding on a line such as `@csrf_exempt` is in the function below it. A lambda or arrow function whose body is one expression, such as `x => x.id`, doesn't count, so a finding on its line stays in the function around it. A method's name includes its class, such as `Views.show`, and an anonymous function takes the name of the variable or field it is assigned to, or is called `anonymous function`. When functions that aren't nested in each other share the line, as in minified code, the line can't tell which one a finding is in, so the lookup returns the function around all of them, or nothing. Lines outside every function, and files in other languages, have no function.

### Triage item

| Field | Type | Meaning |
|---|---|---|
| `item_id` | string | the finding ID, or the group ID for a duplicate group |
| `findings` | list of findings | the member findings, in the format of docs/finding-format.md, with the group's representative first |
| `context.code` | string | the enclosing function, extracted with tree-sitter, or the lines around the findings when no one function holds them all |
| `context.location` | file, start line, end line | where that code is |
| `context.function` | name, start line, end line, optional | the whole enclosing function, also when `context.code` is only a part of it |
| `context.data_flow` | list of locations, optional | the path from user input to the flagged call, when the analyzer reports one |
| `context.injection_suspected` | boolean | true when the code, or a finding's data-flow steps or related locations, have comments or strings that look like instructions to an AI |
| `context.injection_lines` | list of file, start line, end line | the comments or strings that set the flag, which the verdict keeps as `injection_lines` |
| `repo` | scan ID and commit | the checkout that the agent's tools read from |

`ContextCollector` in `backend/app/context/items.py` builds the items, and `scan_items()` in `backend/app/context/store.py` reads the items of a grouped scan from the findings store, leaving out hidden findings. It refuses a scan that hasn't ended as `completed` or `partial`, as `group_scan()` does. The code is the function around all of an item's findings, with its decorators or annotations. When there is no such function, or the file isn't Python, Java, JavaScript or TypeScript, it is the flagged lines with 20 lines before and after them. A function longer than 200 lines is cut the same way, to 200 lines at most. A line longer than 500 characters, as in minified code, is cut around the flagged column, with the cut marked. The lines an adapter masks, the ones Gitleaks flags, stay masked for every finding of the scan in the file, hidden ones too, so a secret doesn't reach the prompt of a nearby item either.

The injection check (`backend/app/context/injection.py`) reads the comments and strings that tree-sitter finds, and every line of a file in another language, such as a template. It reads each line as a person sees it: full-width letters are folded, and invisible characters such as a zero-width space, and Markdown's `*` and backtick, are dropped, so they can't split a word. It is a heuristic: it flags text that talks to an AI, tells the reader to ignore its instructions, uses chat markup such as `[INST]`, copies the shape of the agent's answer, such as `"verdict": "false_positive"`, or tells the reader which verdict to give, such as "mark this as a false positive". A developer's own claim, such as "this is safe because the value is checked", is not flagged, because it doesn't tell anyone what to answer. The phrases are English, so a planted comment in another language gets through.

While it decides, the agent can call two tools:

- `read_file(path, start_line, end_line)` returns lines from the scanned checkout.
- `find_definition(symbol)` returns where a function, class or variable is defined, with its code.

Both tools read only from the scanned checkout. The agent can make at most 5 tool calls per item.

Code goes into a prompt only inside a marked data block, and the prompt tells the model that the block is data to analyze, never instructions to follow. This limits prompt injection through comments in the scanned code (requirement N4).

### Verdict

| Field | Type | Meaning |
|---|---|---|
| `verdict` | `true_positive`, `false_positive` or `unsure` | the decision |
| `reasoning` | string | why, in a few sentences a reviewer can check |
| `cited_lines` | list of file, start line, end line | the code the reasoning relies on |
| `injection_suspected` | boolean | copied from the item, so the review screen can flag it |
| `injection_lines` | list of file, start line, end line | copied from the item, so the review screen can mark the lines |
| `model` | string | the exact version of the model that gave the final verdict |
| `llm_calls` | list of call IDs | every call made for this verdict, in the LLM calls table |

### Severity

| Field | Type | Meaning |
|---|---|---|
| `cvss_v4.vector` | string | the CVSS v4.0 base vector |
| `cvss_v4.score` | number | computed from the vector with FIRST's CVSS v4.0 algorithm, never chosen by the LLM |
| `cvss_v4.level` | `none`, `low`, `medium`, `high` or `critical` | follows from the score |
| `cvss_v4.justifications` | metric to string | one line for each of the 11 base metrics |
| `cvss_v31` | the same four fields for CVSS v3.1, optional | filled only in evaluation runs, for CVEs that only have a v3.1 vector |
| `llm_calls` | list of call IDs | the calls that chose the metrics |

### Example

A triage result for a SQL injection finding. The values are illustrative.

```json
{
  "item_id": "grp-0042",
  "verdict": {
    "verdict": "true_positive",
    "reasoning": "The username parameter from the request is formatted into the SQL string on line 58 and passed to cursor.execute on line 59 without query parameters. Nothing validates it in between.",
    "cited_lines": [{"file": "app/views.py", "start_line": 52, "end_line": 59}],
    "injection_suspected": false,
    "model": "<exact model version>",
    "llm_calls": ["call-0193", "call-0194"]
  },
  "severity": {
    "cvss_v4": {
      "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
      "score": 9.3,
      "level": "critical",
      "justifications": {
        "AV": "Reachable over the network through the login form.",
        "AC": "A single request is enough, with no special conditions.",
        "AT": "No deployment conditions are needed.",
        "PR": "The form is available before login.",
        "UI": "No other user has to do anything.",
        "VC": "The attacker can read every table in the database.",
        "VI": "The attacker can change or delete rows.",
        "VA": "Dropping tables makes the application unusable.",
        "SC": "No other system is affected.",
        "SI": "No other system is affected.",
        "SA": "No other system is affected."
      }
    },
    "llm_calls": ["call-0195"]
  }
}
```

## Report schema

The report service turns an approved finding into a report. It drafts the text through the provider interface, the reviewer can edit any field, and a person approves the text before export. Only approved findings get a report, and only approved text is exported (requirements F5 and F6).

| Field | Type | Meaning |
|---|---|---|
| `report_id` | string | |
| `finding_ids` | list of strings | the approved finding, or every member of an approved group |
| `title` | string | the vulnerability type and where it is, for example "SQL injection in the login form" |
| `summary` | string | two or three sentences on what is wrong and where |
| `impact` | string | what an attacker can do, consistent with the severity |
| `steps_to_reproduce` | list of strings | numbered steps a program's triager can follow |
| `fix` | string | the change that removes the issue, with a code example when it helps |
| `references` | list of URLs | at least the CWE entry, plus any documentation the fix relies on |
| `severity` | the `cvss_v4` fields from the triage result | copied from the finding, or as edited by the reviewer |
| `locations` | list of file and line | the affected code |
| `version` | integer | the version of the text: 1 for the first draft, and one more for each edit or new draft |
| `approved_by`, `approved_at` | string, timestamp | who approved this version of the text, and when. Empty until a person approves it. An edit or a new draft is a new version, so it needs a new approval. |
| `status` | `draft` or `exported` | |
| `created_at`, `exported_at` | timestamps | |

Markdown is the core export format, with one file per report:

```markdown
# SQL injection in the login form

Severity: Critical (CVSS 4.0 score 9.3)
Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N

## Summary

## Impact

## Steps to reproduce

1.

## Fix

## References

- https://cwe.mitre.org/data/definitions/89.html
```

The HackerOne and Bugcrowd formats are stretch goals (T4.2). They use the same fields, with HackerOne's CVSS-based severity and Bugcrowd's VRT priority.
