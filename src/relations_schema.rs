use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::inlineencodings::{Handle, ShortString};
use triblespace::prelude::*;

pub mod playground_relations {
    use super::*;

    attributes! {
        "8F162B593D390E1424394DBF6883A72C" as pub alias: ShortString;
        "F0AD0BBFAC4C4C899637573DC965622E" as pub first_name: Handle<LongString>;
        "764DD765142B3F4725B614BD3B9118EC" as pub last_name: Handle<LongString>;
        "DC0916CB5F640984EFE359A33105CA9A" as pub display_name: Handle<LongString>;
    }
}
