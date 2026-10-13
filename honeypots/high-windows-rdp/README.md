# High Windows RDP recipe

The Windows adapter creates an isolated disk, unattended-install seed and KVM domain. It does not
download Microsoft media implicitly: set `HF_HIGH_WINDOWS_ISO_URL` and
`HF_HIGH_WINDOWS_ISO_SHA256` to an organisation-approved evaluation or licensed ISO. Both are
required; HTTP and checksum-less downloads are refused.

The supplied ISO must be Windows Server evaluation media whose index 2 is Desktop Experience;
this is checked during real-host qualification, because ISO catalogues cannot be inspected by the
agent without mounting untrusted media. Initial installation can take several minutes; the adapter
waits for RDP but never opens VNC/SPICE on a public interface. Host-side operational telemetry is
available immediately. Guest event telemetry still requires a reviewed Windows sensor and serial
transport before this recipe should be used outside controlled validation.
