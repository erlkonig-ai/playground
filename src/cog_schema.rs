use triblespace::macros::id_hex;
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::inlineencodings::{GenId, Handle};
use triblespace::prelude::*;

pub mod playground_cog {
    use super::*;

    attributes! {
        "FA6090FB00EEE2F5EF1E51F1F68EA5B8" as pub context: Handle<LongString>;
        "D986EF113EFA588E6247420A06DA87BA" as pub about_exec_result: GenId;
        "CC8828B7462BFDA45A296C0A12C6333C" as pub moment_boundary_turn_id: GenId;
    }

    #[allow(non_upper_case_globals)]
    pub const playground_cog_metadata: Id = id_hex!("369BE69D185F799CA5370205D34FC120");

    #[allow(non_upper_case_globals)]
    pub const kind_thought: Id = id_hex!("26FA0606BCF4AA73F868B029596828DB");
    #[allow(non_upper_case_globals)]
    pub const kind_moment_boundary: Id = id_hex!("C1E52577C5F7C9066B10FBC7EA844B17");
}

pub fn build_playground_cog_metadata() -> Fragment {
    playground_cog::describe()
}
