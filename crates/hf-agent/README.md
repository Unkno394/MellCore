# HoneyForge Agent

`hf-agent` is the HoneyForge host agent. It manages honeypot runtimes on a Linux host and reports agent and trap events to a HoneyForge control center.

## Install

```sh
cargo install hf-agent --version 0.1.0
```

The agent is normally run as a root-owned system service because it manages container and virtual-machine runtimes. Check the service deployment guide for the required host packages and configuration.

## Run

```sh
hf-agent --help
```

The center URL and enrollment token file can be supplied with `--center-url` and `--enrollment-token-file`, or the corresponding `HF_CENTER_URL` and `HF_ENROLLMENT_TOKEN_FILE` environment variables. High VM standalone mode is intended for local development and requires an explicit dedicated state directory.

## License

Licensed under either of Apache License, Version 2.0 or MIT license, at your option.
