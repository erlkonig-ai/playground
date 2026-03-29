use triblespace::core::blob::schemas::UnknownBlob;
use triblespace::core::metadata;
use triblespace::macros::id_hex;
use triblespace::prelude::blobschemas::LongString;
use triblespace::prelude::valueschemas::{Blake3, GenId, Handle, NsTAIInterval, U256BE};
use triblespace::prelude::*;

pub mod playground_exec {
    use super::*;

    attributes! {
        "79DD6A1A02E598033EDCE5C667E8E3E6" as pub command_text: Handle<Blake3, LongString>;
        "4A7EA49FD72113D2DC497B407994B4F9" as pub cwd: Handle<Blake3, LongString>;
        "17F4EA6F885F359C4CA967EE8478FA13" as pub stdin: Handle<Blake3, UnknownBlob>;
        "FC48EA2441A1EECAC29C6A2032C09C1E" as pub stdin_text: Handle<Blake3, LongString>;
        "7FFF32386EBB2AE92094B7D88DE2743D" as pub timeout_ms: U256BE;
        "6A968C3FA5667F591D7C41B497CE4559" as pub sandbox_profile: GenId;
        "D8910A14B31096DF94DE9E807B87645F" as pub ordered_requested_at: NsTAIInterval;
        "C4C3870642CAB5F55E7E575B1A62E640" as pub about_request: GenId;
        "28D60463309BCEE8C855A9921CA70669" as pub about_message: GenId;
        "90307D583A8F085828E1007AE432BF86" as pub about_thought: GenId;
        "442A275ABC6834231FC65A4B89773ECD" as pub worker: GenId;
        "CCFAE38E0C70AFBBF7223D2DA28A93C7" as pub ordered_started_at: NsTAIInterval;
        "79474B948670C7D0322C309EB65219F8" as pub attempt: U256BE;
        "3BB7917C5E41E494FECE36FFE79FEF23" as pub ordered_finished_at: NsTAIInterval;
        "B68F9025545C7E616EB90C6440220348" as pub exit_code: U256BE;
        "579EA2A82FB6A4D5B1E409D4F7747E2F" as pub stdout: Handle<Blake3, UnknownBlob>;
        "6F1CB839CAE28A34C5107F36EB7939C3" as pub stderr: Handle<Blake3, UnknownBlob>;
        "CA7AF66AAF5105EC15625ED14E1A2AC0" as pub stdout_text: Handle<Blake3, LongString>;
        "BE4D1876B22EAF93AAD1175DB76D1C72" as pub stderr_text: Handle<Blake3, LongString>;
        "26AD99A81ACA4EE8A6C37CE02A4CC53D" as pub duration_ms: U256BE;
        "E9C77284C7DDCF522A8AC4622FE3FB11" as pub error: Handle<Blake3, LongString>;
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

pub fn build_playground_exec_metadata<B>(
    blobs: &mut B,
) -> std::result::Result<Fragment, B::PutError>
where
    B: BlobStore<Blake3>,
{
    let attrs = playground_exec::describe(blobs)?;

    let mut protocol = entity! { ExclusiveId::force_ref(&playground_exec::playground_exec_metadata) @
        metadata::name: blobs.put("playground_exec")?,
        metadata::description: blobs.put("Playground exec protocol.")?,
        metadata::tag: metadata::KIND_PROTOCOL,
        metadata::attribute*: attrs,
    };

    protocol += entity! { ExclusiveId::force_ref(&playground_exec::kind_command_request) @
        metadata::name: blobs.put("kind_command_request")?,
        metadata::description: blobs.put("Command request entity kind.")?,
        metadata::tag: metadata::KIND_TAG,
    };
    protocol += entity! { ExclusiveId::force_ref(&playground_exec::kind_in_progress) @
        metadata::name: blobs.put("kind_in_progress")?,
        metadata::description: blobs.put("Command in-progress entity kind.")?,
        metadata::tag: metadata::KIND_TAG,
    };
    protocol += entity! { ExclusiveId::force_ref(&playground_exec::kind_command_result) @
        metadata::name: blobs.put("kind_command_result")?,
        metadata::description: blobs.put("Command result entity kind.")?,
        metadata::tag: metadata::KIND_TAG,
    };
    protocol += entity! { ExclusiveId::force_ref(&playground_exec::kind_timeout_extension) @
        metadata::name: blobs.put("kind_timeout_extension")?,
        metadata::description: blobs.put("Control event that extends the deadline for an in-flight command.")?,
        metadata::tag: metadata::KIND_TAG,
    };

    Ok(protocol)
}
