use crate::domain::data_stores::{UserStore, UserStoreError};
use crate::domain::user::{Email, Password, User};
use std::collections::HashMap;

// TODO: Create a new struct called `HashmapUserStore` containing a `users` field
// which stores a `HashMap`` of email `String`s mapped to `User` objects.
// Derive the `Default` trait for `HashmapUserStore`.
#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        // Return `UserStoreError::UserAlreadyExists` if the user already exists,
        // otherwise insert the user into the hashmap and return `Ok(())`.
        if self.users.contains_key(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }
        self.users.insert(user.email.to_owned(), user);
        Ok(())
    }

    // TODO: Implement a public method called `get_user`, which takes an
    // immutable reference to self and an email string slice as arguments.
    // This function should return a `Result` type containing either a
    // `User` object or a `UserStoreError`.
    // Return `UserStoreError::UserNotFound` if the user can not be found.
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        self.users.get(email).ok_or(UserStoreError::UserNotFound).cloned()
    }

    // TODO: Implement a public method called `validate_user`, which takes an
    // immutable reference to self, an email string slice, and a password string slice
    // as arguments. `validate_user` should return a `Result` type containing either a
    // unit type `()` if the email/password passed in match an existing user, or a `UserStoreError`.
    // Return `UserStoreError::UserNotFound` if the user can not be found.
    // Return `UserStoreError::InvalidCredentials` if the password is incorrect.
    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;
        if user.password.as_ref() == password.as_ref() {
            Ok(())
        } else {
            Err(UserStoreError::InvalidCredentials)
        }
    }
}

// TODO: Add unit tests for your `HashmapUserStore` implementation
#[cfg(test)]
mod tests {
    use crate::domain::data_stores::UserStore;
    use crate::domain::user::{Email, Password, User};
    use crate::services::hashmap_user_store::{HashmapUserStore, UserStoreError};

    #[tokio::test]
    async fn test_add_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new(
            Email::parse("test@example.com").unwrap(),
            Password::parse("password").unwrap(),
            false,
        );
        assert!(store.add_user(user).await.is_ok());
    }

    #[tokio::test]
    async fn test_get_user_and_found() {
        let mut store = HashmapUserStore::default();
        let user = User::new(
            Email::parse("test@example.com").unwrap(),
            Password::parse("password").unwrap(),
            false,
        );
        store.add_user(user.clone()).await.unwrap();
        let found_user = store.get_user(&user.email).await.unwrap();
        assert_eq!(found_user.email, user.email);
        assert_eq!(found_user.password, user.password);
        assert_eq!(found_user.requires_2fa, user.requires_2fa);
    }

    #[tokio::test]
    async fn test_get_user_and_not_found() {
        let store = HashmapUserStore::default();
        let user = User::new(
            Email::parse("test@example.com").unwrap(),
            Password::parse("password").unwrap(),
            false,
        );
        assert!(store.get_user(&user.email).await.is_err());
        assert_eq!(
            store.get_user(&user.email).await.unwrap_err(),
            UserStoreError::UserNotFound
        );
    }
    #[tokio::test]
    async fn test_validate_user_ok() {
        let mut store = HashmapUserStore::default();
        let user = User::new(
            Email::parse("test@example.com").unwrap(),
            Password::parse("password").unwrap(),
            false,
        );
        store.add_user(user.clone()).await.unwrap();
        assert!(store.validate_user(&user.email, &user.password).await.is_ok());
    }
    #[tokio::test]
    async fn test_validate_user_credentials_error() {
        let mut store = HashmapUserStore::default();
        let wrong_password = Password::parse("wrong_password").unwrap();
        let user = User::new(
            Email::parse("test@example.com").unwrap(),
            Password::parse("password").unwrap(),
            false,
        );
        store.add_user(user.clone()).await.unwrap();
        assert!(store.validate_user(&user.email, &wrong_password).await.is_err());
        assert_eq!(
            store.validate_user(&user.email, &wrong_password).await.unwrap_err(),
            UserStoreError::InvalidCredentials
        )
    }
}
