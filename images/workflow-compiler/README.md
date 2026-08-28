# Clusterflux workflow compiler appliance

This image is a rustc-only appliance for `.clusterflux/**/*.rs`. Run it only
through the node compiler lane, which pins the OCI digest and gVisor `runsc`
version, selects `platform=systrap`, disables networking, and exposes only a
read-only source mount plus one fresh output directory.

The final image deliberately contains no Cargo, Git, download client, package
manager workflow, repository checkout, or credentials.
