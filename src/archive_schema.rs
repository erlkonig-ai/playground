use triblespace::prelude::blobschemas::LongString;
use triblespace::prelude::valueschemas::{Blake3, GenId, Handle, NsTAIInterval, OrderedNsTAIInterval, ShortString};
use triblespace::prelude::*;

pub mod playground_archive {
    use super::*;

    attributes! {
        "0D9195A7B1B20DE312A08ECE39168079" as pub reply_to: GenId;
        "838CC157FFDD37C6AC7CC5A472E43ADB" as pub author: GenId;
        "E63EE961ABDB1D1BEC0789FDAFFB9501" as pub author_name: Handle<Blake3, LongString>;
        "ACF09FF3D62B73983A222313FF0C52D2" as pub content: Handle<Blake3, LongString>;
        "0DA5DD275AA34F86B0297CC35F1B7395" as pub created_at: NsTAIInterval;
        "59FA7C04A43B96F31414D1B4544FAEC2" as pub ordered_created_at: OrderedNsTAIInterval;
    }
}

pub mod playground_archive_import {
    use super::*;

    attributes! {
        "891508CAD6E1430B221ADA937EFBD982" as pub batch: GenId;
        "E997DCAAF43BAA04790FCB0FA0FBFE3A" as pub source_format: ShortString;
        "87B587A3906056038FD767F4225274F9" as pub source_conversation_id: Handle<Blake3, LongString>;
        "1B2A09FF44D2A5736FA320AB255026C1" as pub source_message_id: Handle<Blake3, LongString>;
        "AA3CF220F15CCF724276F1251AFE053B" as pub source_author: Handle<Blake3, LongString>;
        "B4C084B61FB46A932BFCA75B8BC621FA" as pub source_role: Handle<Blake3, LongString>;
    }
}
