use sp1_sdk::{blocking::MockProver, blocking::Prover, include_elf, Elf, HashableKey, ProvingKey};
const ELF: Elf = include_elf!("agent-batch-program");
fn main() {
    let pk = MockProver::new().setup(ELF).expect("setup");
    println!("{}", pk.verifying_key().bytes32());
}
