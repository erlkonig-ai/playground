use triblespace::macros::id_hex;
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::inlineencodings::{GenId, Handle, ShortString, U256BE};
use triblespace::prelude::*;

pub mod model_chat {
    use super::*;

    attributes! {
        "5A14A02113CE43A59881D0717726F465" as pub about_request: GenId;
        "DA8E31E47919337B3E00724EBE32D14E" as pub about_thought: GenId;
        "C1FFE9D4FEC549C09C96639665561DFE" as pub model: ShortString;
        "B6BF5BEE9961D6C0F4F825088DD2C3F2" as pub context: Handle<LongString>;
        "430B9CD43A3BC414E730B29BCFD6349B" as pub request_raw: Handle<LongString>;
        "4FC561A8EC8E9D750445AE8A0BE5E094" as pub worker: GenId;
        "8CAEF4617646F8C9E90BC9A3ED3D0496" as pub attempt: U256BE;
        "B1B904590F0FA70AD1BA247F3D23A6CC" as pub output_text: Handle<LongString>;
        "9CD6494CB9825D01A2E86C7E2A56CA96" as pub response_id: Handle<LongString>;
        "E41A91D2C68640AA86AB31A2CAB2858F" as pub response_raw: Handle<LongString>;
        "567E35DACDB00C799E75AEED0B6EFDF7" as pub reasoning_text: Handle<LongString>;
        "BD1635514288254E9CB0448CC07C8B65" as pub response_json_root: GenId;
        "9E9B829C473E416E9150D4B94A6A2DC4" as pub error: Handle<LongString>;
        "115637F43C28E6ABE3A1B0C4095CAC03" as pub input_tokens: U256BE;
        "F17EB3EABC10A0210403B807BEB25D08" as pub output_tokens: U256BE;
        "B680DCFAB2E8D1413E450C89AB156197" as pub cache_creation_input_tokens: U256BE;
        "0A9C7D70295A65413375842916821032" as pub cache_read_input_tokens: U256BE;
    }

    #[allow(non_upper_case_globals, dead_code)]
    pub const model_chat_metadata: Id = id_hex!("E714890E7F711B393B6249A3E7198B89");

    #[allow(non_upper_case_globals)]
    pub const kind_request: Id = id_hex!("1524B4C030D4F10365D9DCEE801A09C8");
    #[allow(non_upper_case_globals)]
    pub const kind_in_progress: Id = id_hex!("16C69FC4928D54BF93E6F3222B4685A7");
    #[allow(non_upper_case_globals)]
    pub const kind_result: Id = id_hex!("DE498E4697F9F01219C75E7BC183DB91");
}

pub fn build_model_chat_metadata() -> Fragment {
    model_chat::describe()
}
