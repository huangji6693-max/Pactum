pragma circom 2.1.5;

include "./commitment_hash.circom";
include "./batch_merkle.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

// SingleStepTransition verifies a single instruction execution step `k -> k + 1`
// narrowed down by the interactive bisection dispute protocol (Issue #305):
//   next_state_root = Poseidon(pre_state_root, commitment_id, step_index, opcode)
template SingleStepTransition() {
    signal input pre_state_root;
    signal input commitment_id;
    signal input step_index;
    signal input opcode;
    signal output post_state_root;

    component hasher = Poseidon(4);
    hasher.inputs[0] <== pre_state_root;
    hasher.inputs[1] <== commitment_id;
    hasher.inputs[2] <== step_index;
    hasher.inputs[3] <== opcode;

    post_state_root <== hasher.out;
}

// BisectionFraudProof combines single-step transition verification with
// batch Merkle inclusion for the narrowed-down disputed step `step_index` in [0, 2^BATCH_DEPTH).
template FraudProof(BATCH_DEPTH) {
    // ── Public inputs ─────────────────────────────────────────────────
    signal input pre_state_root;          // Agreed state root at step `low`
    signal input claimed_post_state_root; // Sequencer's claimed state root at step `low + 1`
    signal input correct_post_state_root; // Honest single-step transition output
    signal input claimed_batch_root;      // Sequencer's registered batch root
    signal input correct_batch_root;      // Recomputed batch Merkle root

    // ── Private witness inputs for the single disputed instruction ────
    signal input step_index;
    signal input opcode;
    signal input issuer_hash;
    signal input counterparty_hash;
    signal input terms_hash;
    signal input due_at;
    signal input siblings[BATCH_DEPTH];
    signal input path_bits[BATCH_DEPTH];

    // 1. Compute the commitment leaf hash for the disputed step
    component ch = CommitmentHash();
    ch.issuer_hash       <== issuer_hash;
    ch.counterparty_hash <== counterparty_hash;
    ch.terms_hash        <== terms_hash;
    ch.due_at            <== due_at;

    // 2. Execute the single-instruction state transition constraint
    component step = SingleStepTransition();
    step.pre_state_root <== pre_state_root;
    step.commitment_id  <== ch.commitment_id;
    step.step_index     <== step_index;
    step.opcode         <== opcode;
    step.post_state_root === correct_post_state_root;

    // 3. Verify Merkle path for the commitment leaf in the batch
    component mt = BatchMerkleVerify(BATCH_DEPTH);
    mt.leaf <== ch.commitment_id;
    mt.root <== correct_batch_root;
    for (var i = 0; i < BATCH_DEPTH; i++) {
        mt.siblings[i]  <== siblings[i];
        mt.path_bits[i] <== path_bits[i];
    }

    // Bind claimed public signals into constraints so they cannot be optimized out
    signal claimed_post_sink;
    claimed_post_sink <== claimed_post_state_root * 1;
    signal claimed_batch_sink;
    claimed_batch_sink <== claimed_batch_root * 1;
}

component main {
    public [
        pre_state_root,
        claimed_post_state_root,
        correct_post_state_root,
        claimed_batch_root,
        correct_batch_root
    ]
} = FraudProof(10);
