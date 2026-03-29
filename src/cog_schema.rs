use triblespace::core::metadata;
use triblespace::macros::id_hex;
use triblespace::prelude::blobschemas::LongString;
use triblespace::prelude::valueschemas::{Blake3, GenId, Handle, NsTAIInterval};
use triblespace::prelude::*;

pub mod playground_cog {
    use super::*;

    attributes! {
        "FA6090FB00EEE2F5EF1E51F1F68EA5B8" as pub context: Handle<Blake3, LongString>;
        "1AE17985F2AE74631CE16FD84DC97FB4" as pub ordered_created_at: NsTAIInterval;
        "D986EF113EFA588E6247420A06DA87BA" as pub about_exec_result: GenId;
        "CC8828B7462BFDA45A296C0A12C6333C" as pub moment_boundary_turn_id: GenId;
    }

    /// Root id for describing the playground_cog protocol.
    #[allow(non_upper_case_globals)]
    pub const playground_cog_metadata: Id = id_hex!("369BE69D185F799CA5370205D34FC120");

    /// Tag for thought entities.
    #[allow(non_upper_case_globals)]
    pub const kind_thought: Id = id_hex!("26FA0606BCF4AA73F868B029596828DB");
    /// Tag for moment-boundary marker entities.
    #[allow(non_upper_case_globals)]
    pub const kind_moment_boundary: Id = id_hex!("C1E52577C5F7C9066B10FBC7EA844B17");

}

pub fn build_playground_cog_metadata<B>(
    blobs: &mut B,
) -> std::result::Result<Fragment, B::PutError>
where
    B: BlobStore<Blake3>,
{
    let attrs = playground_cog::describe(blobs)?;

    let mut protocol = entity! { ExclusiveId::force_ref(&playground_cog::playground_cog_metadata) @
        metadata::name: blobs.put("playground_cog")?,
        metadata::description: blobs.put("Playground cog protocol.")?,
        metadata::tag: metadata::KIND_PROTOCOL,
        metadata::attribute*: attrs,
    };

    protocol += entity! { ExclusiveId::force_ref(&playground_cog::kind_thought) @
        metadata::name: blobs.put("kind_thought")?,
        metadata::description: blobs.put("Thought entity kind.")?,
        metadata::tag: metadata::KIND_TAG,
    };
    protocol += entity! { ExclusiveId::force_ref(&playground_cog::kind_moment_boundary) @
        metadata::name: blobs.put("kind_moment_boundary")?,
        metadata::description: blobs.put("Moment-boundary marker entity kind.")?,
        metadata::tag: metadata::KIND_TAG,
    };

    Ok(protocol)
}
