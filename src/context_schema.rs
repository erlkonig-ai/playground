use triblespace::core::metadata;
use triblespace::macros::id_hex;
use triblespace::prelude::blobschemas::LongString;
use triblespace::prelude::valueschemas::{
    Blake3, GenId, Handle, NsTAIInterval,
};
use triblespace::prelude::*;

pub mod playground_context {
    use super::*;

    attributes! {
        "3292CF0B3B6077991D8ECE6E2973D4B6" as pub summary: Handle<Blake3, LongString>;
        "4036F38AB05D26764A1E5E456337F399" as pub ordered_created_at: NsTAIInterval;
        "502F7D33822A90366F0F0ADA0556177F" as pub ordered_start_at: NsTAIInterval;
        "DF84E872EB68FBFCA63D760F27FD8A6F" as pub ordered_end_at: NsTAIInterval;
        "CB97C36A32DEC70E0D1149E7C5D88588" as pub left: GenId;
        "087D07E3D9D94F0C4E96813C7BC5E74C" as pub right: GenId;
        "9B83D68AECD6888AA9CE95E754494768" as pub child: GenId;
        "316834CC6B0EA6F073BF5362D67AC530" as pub about_exec_result: GenId;
        "A4E2B712CA28AB1EED76C34DE72AFA39" as pub about_archive_message: GenId;
    }

    /// Root id for describing the playground_context protocol.
    #[allow(non_upper_case_globals)]
    pub const playground_context_metadata: Id = id_hex!("2B490ED2CEAC5496F7F9601724B99A48");

    /// Tag for context chunk entities.
    #[allow(non_upper_case_globals)]
    pub const kind_chunk: Id = id_hex!("40E6004417F9B767AFF1F138DE3D3AAC");

}

pub fn build_playground_context_metadata<B>(
    blobs: &mut B,
) -> std::result::Result<Fragment, B::PutError>
where
    B: BlobStore<Blake3>,
{
    let attrs = playground_context::describe(blobs)?;

    let mut protocol = entity! { ExclusiveId::force_ref(&playground_context::playground_context_metadata) @
        metadata::name: blobs.put("playground_context")?,
        metadata::description: blobs.put("Playground context protocol.")?,
        metadata::tag: metadata::KIND_PROTOCOL,
        metadata::attribute*: attrs,
    };

    protocol += entity! { ExclusiveId::force_ref(&playground_context::kind_chunk) @
        metadata::name: blobs.put("kind_chunk")?,
        metadata::description: blobs.put("Context chunk entity kind.")?,
        metadata::tag: metadata::KIND_TAG,
    };

    Ok(protocol)
}
