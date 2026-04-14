use super::{Email, HashedPassword};
use sqlx::FromRow;

// The User struct should contain 3 fields. email, which is a String;
// password, which is also a String; and requires_2fa, which is a boolean.
#[derive(Clone, Debug, PartialEq, FromRow)]
pub struct User {
    pub email: Email,
    pub password: HashedPassword,
    pub requires_2fa: bool,
}

impl User {
    // add a constructor function called `new`
    pub fn new(email: Email, password: HashedPassword, requires_2fa: bool) -> Self {
        Self {
            email,
            password,
            requires_2fa,
        }
    }
}
