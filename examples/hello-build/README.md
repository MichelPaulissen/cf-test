# Hello build

The primary Clusterflux example snapshots this project, compiles a real static C
executable in the declared network-disabled Linux execution environment, and publishes the
executable as a retained artifact.

Run it with:

~~~bash
clusterflux bundle inspect --project examples/hello-build
clusterflux run --project examples/hello-build build
clusterflux artifact list --process <process-id>
clusterflux artifact download <artifact-id> --to ./hello-clusterflux
chmod +x ./hello-clusterflux
./hello-clusterflux
~~~

The final command prints hello from a real Clusterflux build.
