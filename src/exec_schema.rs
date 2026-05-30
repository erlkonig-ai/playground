use triblespace::core::blob::encodings::UnknownBlob;
use triblespace::macros::id_hex;
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::inlineencodings::{GenId, Handle, U256BE};
use triblespace::prelude::*;

pub mod playground_exec {
    use super::*;

    attributes! {
        "79DD6A1A02E598033EDCE5C667E8E3E6" as pub command_text: Handle<LongString>;
        "4A7EA49FD72113D2DC497B407994B4F9" as pub cwd: Handle<LongString>;
        "17F4EA6F885F359C4CA967EE8478FA13" as pub stdin: Handle<UnknownBlob>;
        "FC48EA2441A1EECAC29C6A2032C09C1E" as pub stdin_text: Handle<LongString>;
        "7FFF32386EBB2AE92094B7D88DE2743D" as pub timeout_ms: U256BE;
        "6A968C3FA5667F591D7C41B497CE4559" as pub sandbox_profile: GenId;
        "C4C3870642CAB5F55E7E575B1A62E640" as pub about_request: GenId;
        "28D60463309BCEE8C855A9921CA70669" as pub about_message: GenId;
        "90307D583A8F085828E1007AE432BF86" as pub about_thought: GenId;
        "442A275ABC6834231FC65A4B89773ECD" as pub worker: GenId;
        "79474B948670C7D0322C309EB65219F8" as pub attempt: U256BE;
        "B68F9025545C7E616EB90C6440220348" as pub exit_code: U256BE;
        "579EA2A82FB6A4D5B1E409D4F7747E2F" as pub stdout: Handle<UnknownBlob>;
        "6F1CB839CAE28A34C5107F36EB7939C3" as pub stderr: Handle<UnknownBlob>;
        "CA7AF66AAF5105EC15625ED14E1A2AC0" as pub stdout_text: Handle<LongString>;
        "BE4D1876B22EAF93AAD1175DB76D1C72" as pub stderr_text: Handle<LongString>;
        "26AD99A81ACA4EE8A6C37CE02A4CC53D" as pub duration_ms: U256BE;
        "E9C77284C7DDCF522A8AC4622FE3FB11" as pub error: Handle<LongString>;
    }

    #[allow(non_upper_case_globals)]
    pub const playground_exec_metadata: Id = id_hex!("94563964DFC622200FAE6E5383D0B4FC");

    #[allow(non_upper_case_globals)]
    pub const kind_command_request: Id = id_hex!("3D2512DAE86B14B9049930F3146A3188");
    #[allow(non_upper_case_globals)]
    pub const kind_in_progress: Id = id_hex!("2D81A8D840822CF082DE5DE569B53730");
    #[allow(non_upper_case_globals)]
    pub const kind_command_result: Id = id_hex!("DF7165210F066E84D93E9A430BB0D4BD");
    #[allow(non_upper_case_globals)]
    pub const kind_timeout_extension: Id = id_hex!("75BC66A1C39131B9A0975613AC9B59FD");

}

pub fn build_playground_exec_metadata() -> Fragment {
    playground_exec::describe()
}
