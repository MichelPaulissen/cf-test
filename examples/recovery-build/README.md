# Recovery build

This advanced example starts two instances of the same task definition. The
stable lane completes while the recovering lane executes a real failing command
under AwaitOperator. Edit the failing command to write
/clusterflux/output/recovering.txt, then restart that task from the debugger or
CLI. The original main join completes from the replacement attempt.
