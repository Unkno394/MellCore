use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Permissions(pub u16);

impl Permissions {
    pub const fn file() -> Self {
        Self(0o644)
    }
    pub const fn dir() -> Self {
        Self(0o755)
    }
    pub fn display(self, directory: bool) -> String {
        let mut value = String::with_capacity(10);
        value.push(if directory { 'd' } else { '-' });
        for shift in [6, 3, 0] {
            let bits = (self.0 >> shift) & 7;
            value.push(if bits & 4 != 0 { 'r' } else { '-' });
            value.push(if bits & 2 != 0 { 'w' } else { '-' });
            value.push(if bits & 1 != 0 { 'x' } else { '-' });
        }
        value
    }
}
