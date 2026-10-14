//! IEC 60870-5-104 (IEC-104) honeypot trap implementation.

use crate::session::Session;

pub struct Iec104Trap;

impl Iec104Trap {
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
    fn test_iec104_stub() {
        assert!(true);
    }
}
