//! Extended Low-Interaction Traps (Discovery, Probing, Network Services).

use crate::session::Session;

pub struct LowExtraTrap;

impl LowExtraTrap {
    pub fn new(_params: &serde_json::Value) -> Result<Self, String> {
        Ok(Self)
    }

    pub async fn handle(&self, _s: &mut Session) {
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]

    #[test]
    fn test_low_extra_stub() {
        assert!(true);
    }
}
