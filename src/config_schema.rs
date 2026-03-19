use triblespace::core::metadata;
use triblespace::macros::id_hex;
use triblespace::prelude::blobschemas::LongString;
use triblespace::prelude::valueschemas::{Blake3, GenId, Handle, NsTAIInterval, U256BE};
use triblespace::prelude::*;

pub mod playground_config {
    use super::*;

    attributes! {
        "DDF83FEC915816ACAE7F3FEBB57E5137" as pub updated_at: NsTAIInterval;
        "950B556A74F71AC7CB008AB23FBB6544" as pub system_prompt: Handle<Blake3, LongString>;
        "35E36AE7B60AD946661BD63B3CD64672" as pub branch: Handle<Blake3, LongString>;
        "F0F90572249284CD57E48580369DEB6D" as pub author: Handle<Blake3, LongString>;
        "98A194178CFD7CBB915C1BC9EB561A7F" as pub author_role: Handle<Blake3, LongString>;
        "D1DC11B303725409AB8A30C6B59DB2D7" as pub persona_id: GenId;
        "79E1B50756FB64A30916E9353225E179" as pub active_model_profile_id: GenId;
        "698519DFB681FABC3F06160ACAC9DA8E" as pub poll_ms: U256BE;
        "6691CF3F872C6107DCFAD0BCF7CDC1A0" as pub model_profile_id: GenId;
        "85BE7BDA465B3CB0F800F76EEF8FAC9B" as pub model_name: Handle<Blake3, LongString>;
        "B216CFBBF85AA1350B142D510E26268B" as pub model_base_url: Handle<Blake3, LongString>;
        "55F3FFD721AF7C1258E45BC91CDBF30F" as pub model_api_key: Handle<Blake3, LongString>;
        "328B29CE81665EE719C5A6E91695D4D4" as pub tavily_api_key: Handle<Blake3, LongString>;
        "AB0DF9F03F28A27A6DB95B693CC0EC53" as pub exa_api_key: Handle<Blake3, LongString>;
        "BA4E05799CA2ACDCF3F9350FC8742F2F" as pub model_reasoning_effort: Handle<Blake3, LongString>;
        "5F04F7A0EB4EBBE6161022B336F83513" as pub model_stream: U256BE;
        "F9CEA1A2E81D738BB125B4D144B7A746" as pub model_context_window_tokens: U256BE;
        "4200F6746B36F2784DEBA1555595D6AC" as pub model_max_output_tokens: U256BE;
        "1FF004BB48F7A4F8F72541F4D4FA75FF" as pub model_context_safety_margin_tokens: U256BE;
        "095FAECDB8FF205DF591DF594E593B01" as pub model_chars_per_token: U256BE;
        "7F3D8D944C0DCDFEFDE7A1E4CB4F9780" as pub model_max_inline_images: U256BE;
        "3DFAC4072FB6BB7051A470F457F3AAD2" as pub model_max_inline_image_bytes: U256BE;
        "18AA5BED17D29C24832DDAF2E81905AA" as pub model_vision: U256BE;
        "120F9C6BBB103FAFFB31A66E2ABC15E6" as pub exec_default_cwd: Handle<Blake3, LongString>;
        "D18A351B6E03A460E4F400D97D285F96" as pub exec_sandbox_profile: GenId;
    }

    /// Root id for describing the playground_config protocol.
    #[allow(non_upper_case_globals)]
    pub const playground_config_metadata: Id = id_hex!("F696CB4F22D5EAEE7E42A820F9458A35");

    /// Tag for configuration entries.
    #[allow(non_upper_case_globals)]
    pub const kind_config: Id = id_hex!("A8DCBFD625F386AA7CDFD62A81183E82");
    /// Tag for model profile entries (versioned by `updated_at`).
    #[allow(non_upper_case_globals)]
    pub const kind_model_profile: Id = id_hex!("B08E356C4B08F44AB7EC177D47129447");

}

pub fn build_playground_config_metadata<B>(
    blobs: &mut B,
) -> std::result::Result<Fragment, B::PutError>
where
    B: BlobStore<Blake3>,
{
    let attrs = playground_config::describe(blobs)?;

    let mut protocol = entity! { ExclusiveId::force_ref(&playground_config::playground_config_metadata) @
        metadata::name: blobs.put("playground_config")?,
        metadata::description: blobs.put("Playground config protocol.")?,
        metadata::tag: metadata::KIND_PROTOCOL,
        metadata::attribute*: attrs,
    };

    protocol += entity! { ExclusiveId::force_ref(&playground_config::kind_config) @
        metadata::name: blobs.put("kind_config")?,
        metadata::description: blobs.put("Configuration entry entity kind.")?,
        metadata::tag: metadata::KIND_TAG,
    };
    protocol += entity! { ExclusiveId::force_ref(&playground_config::kind_model_profile) @
        metadata::name: blobs.put("kind_model_profile")?,
        metadata::description: blobs.put("Model profile entry entity kind.")?,
        metadata::tag: metadata::KIND_TAG,
    };

    Ok(protocol)
}
