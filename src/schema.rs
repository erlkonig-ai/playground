#[path = "cog_schema.rs"]
mod cog_schema;
#[path = "config_schema.rs"]
mod config_schema;
#[path = "context_schema.rs"]
mod context_schema;
#[path = "exec_schema.rs"]
mod exec_schema;
#[path = "model_chat_schema.rs"]
mod model_chat_schema;

pub use cog_schema::playground_cog;
pub use config_schema::playground_config;
pub use context_schema::playground_context;
pub use exec_schema::playground_exec;
pub use model_chat_schema::model_chat;

pub fn build_playground_metadata() -> triblespace::prelude::Fragment {
    let mut bundle = exec_schema::build_playground_exec_metadata();
    bundle += config_schema::build_playground_config_metadata();
    bundle += cog_schema::build_playground_cog_metadata();
    bundle += context_schema::build_playground_context_metadata();
    bundle += model_chat_schema::build_model_chat_metadata();
    bundle
}
