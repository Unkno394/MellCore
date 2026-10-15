# High custom ISO

This adapter boots a verified x86_64 ISO on the isolated High network with SPICE bound to
localhost and never creates DNAT.

The agent inspects the ISO before launch and selects an explicit adapter: Ubuntu Server uses
Subiquity autoinstall, Debian uses preseed, and Arch Linux uses its distribution install tools
through an isolated serial console. Each recipe installs SSH, QEMU Guest Agent and the High
telemetry sensor, ejects the ISO, reboots from the target disk and creates the host-side verified
marker only after post-reboot readiness. Windows media is routed to its Autounattend adapter.
NixOS and other user-supplied media are not advertised as built-in profiles. Unknown media is
rejected with an interactive-install diagnostic; merely booting a Live environment is never
considered a completed deployment.
