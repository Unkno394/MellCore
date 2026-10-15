# High custom ISO (best effort)

This adapter boots a verified x86_64 ISO on the isolated High network with SPICE bound to
localhost. It never creates DNAT. It does not claim unattended support for arbitrary installers;
deployment succeeds only if the media's own automation installs and enables SSH on port 22.
