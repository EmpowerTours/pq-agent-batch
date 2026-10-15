use sp1_build::{build_program_with_args, BuildArgs};
// Local (non-docker) build for cycle measurement. For a vkey that will be pinned
// on chain, switch to docker: true + tag like quantum-portfolio/zk-mldsa does.
fn main() {
    build_program_with_args("../program", BuildArgs { ..Default::default() });
}
