use crate::domain::{Email, Password, User, UserStore, UserStoreError};
use std::collections::HashMap;

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
        self.users.insert(user.email.clone(), user);
        Ok(())
    }
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        match self.users.get(email) {
            Some(user) => Ok(user.clone()),
            None => Err(UserStoreError::UserNotFound),
        }
        //self.users.get(email).ok_or(UserStoreError::UserNotFound).cloned()
    }

    async fn validate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<(), UserStoreError> {
        match self.users.get(email) {
            Some(user) => {
                if user.password.eq(password) {
                    Ok(())
                } else {
                    Err(UserStoreError::InvalidCredentials)
                }
            }
            None => Err(UserStoreError::UserNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::data_stores::UserStore;
    use crate::domain::user::User;
    use crate::domain::{Email, Password};
    use crate::services::hashmap_user_store::{HashmapUserStore, UserStoreError};

    #[tokio::test]
    async fn test_add_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new(
            Email::parse("test@example.com".to_owned()).unwrap(),
            Password::parse("password".to_owned()).unwrap(),
            false,
        );
        assert!(store.add_user(user.clone()).await.is_ok());

        // Test adding an existing user
        let result = store.add_user(user).await;
        assert_eq!(result, Err(UserStoreError::UserAlreadyExists));
    }

    #[tokio::test]
    async fn test_get_user_and_found() {
        let mut store = HashmapUserStore::default();
        let email = Email::parse("test@example.com".to_owned()).unwrap();

        let user = User {
            email: email.clone(),
            password: Password::parse("password".to_owned()).unwrap(),
            requires_2fa: false,
        };
        store.users.insert(email, user.clone());

        let result = store.get_user(&user.email).await;
        assert_eq!(result, Ok(user));
    }

    #[tokio::test]
    async fn test_get_user_and_not_found() {
        let store = HashmapUserStore::default();
        let user = User::new(
            Email::parse("test@example.com".to_owned()).unwrap(),
            Password::parse("password".to_owned()).unwrap(),
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
            Email::parse("test@example.com".to_owned()).unwrap(),
            Password::parse("password".to_owned()).unwrap(),
            false,
        );

        store.users.insert(user.email.clone(), user.clone());

        assert!(store
            .validate_user(&user.email, &user.password)
            .await
            .is_ok());
    }
    #[tokio::test]
    async fn test_validate_user_credentials_error() {
        let mut store = HashmapUserStore::default();
        let wrong_password = Password::parse("wrong_password".to_owned()).unwrap();
        let user = User::new(
            Email::parse("test@example.com".to_owned()).unwrap(),
            Password::parse("password".to_owned()).unwrap(),
            false,
        );
        store.users.insert(user.email.clone(), user.clone());

        assert!(store
            .validate_user(&user.email, &wrong_password)
            .await
            .is_err());
        assert_eq!(
            store
                .validate_user(&user.email, &wrong_password)
                .await
                .unwrap_err(),
            UserStoreError::InvalidCredentials
        )
    }
}
