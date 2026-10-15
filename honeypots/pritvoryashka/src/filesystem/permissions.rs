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
        if self.0 & 0o4000 != 0 {
            value.replace_range(3..4, if self.0 & 0o100 != 0 { "s" } else { "S" });
        }
        if self.0 & 0o2000 != 0 {
            value.replace_range(6..7, if self.0 & 0o010 != 0 { "s" } else { "S" });
        }
        if self.0 & 0o1000 != 0 {
            value.replace_range(9..10, if self.0 & 0o001 != 0 { "t" } else { "T" });
        }
        value
    }
}
