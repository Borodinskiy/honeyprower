//! SCADA (Modbus TCP / Industrial HMI) honeypot trap implementation.

use crate::session::Session;

pub struct ScadaTrap;

impl ScadaTrap {
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
    fn test_scada_stub() {
        assert!(true);
    }
}
