#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct Email(String);

impl AsRef<String> for Email {
    fn as_ref(&self) -> &String {
        &self.0 // Returns a reference to the inner String's content
    }
}
impl Email {
    // - email is empty or does not contain '@'
    pub fn parse(email: &str) -> Result<Self, String> {
        if email.contains('@') {
            Ok(Email(email.to_string()))
        } else {
            Err("Email is not valid".to_string())
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Password(String);

impl AsRef<String> for Password {
    fn as_ref(&self) -> &String {
        &self.0 // Returns a reference to the inner String's content
    }
}
impl Password {
    // - password is less than 8 characters
    pub fn parse(password: &str) -> Result<Self, String> {
        if password.len() >= 8 {
            Ok(Password(password.to_string()))
        } else {
            Err("Password is not valid".to_string())
        }
    }
}

// The User struct should contain 3 fields. email, which is a String;
// password, which is also a String; and requires_2fa, which is a boolean.
// TODO: Validate if is correct
#[derive(Clone, Debug, PartialEq)]
pub struct User {
    pub email: Email,
    pub password: Password,
    pub requires_2fa: bool,
}

impl User {
    // add a constructor function called `new`
    pub fn new(email: Email, password: Password, requires_2fa: bool) -> Self {
        User {
            email,
            password,
            requires_2fa,
        }
    }
}
