use std::error::Error as StdError;

pub(crate) type CliResult<T> = std::result::Result<T, CliError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CliErrorClass {
    General,
    Usage,
    Password,
}

#[derive(Debug)]
pub(crate) struct CliError {
    class: CliErrorClass,
    message: String,
}

impl CliError {
    pub(crate) fn general(message: impl Into<String>) -> Self {
        Self {
            class: CliErrorClass::General,
            message: message.into(),
        }
    }

    pub(crate) fn usage(message: impl Into<String>) -> Self {
        Self {
            class: CliErrorClass::Usage,
            message: message.into(),
        }
    }

    pub(crate) fn password(message: impl Into<String>) -> Self {
        Self {
            class: CliErrorClass::Password,
            message: message.into(),
        }
    }

    pub(crate) fn exit_code(&self) -> i32 {
        match self.class {
            CliErrorClass::General => 1,
            CliErrorClass::Usage => 2,
            CliErrorClass::Password => 3,
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl StdError for CliError {}

impl From<&str> for CliError {
    fn from(message: &str) -> Self {
        Self::general(message)
    }
}

impl From<String> for CliError {
    fn from(message: String) -> Self {
        Self::general(message)
    }
}

impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        Self::general(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_classes_preserve_messages_and_standard_error_behavior() {
        for (error, code) in [
            (CliError::general("operation failed"), 1),
            (CliError::usage("invalid arguments"), 2),
            (CliError::password("password required"), 3),
        ] {
            assert_eq!(error.exit_code(), code);
            assert_eq!(format!("{error}"), error.message);
            assert!(StdError::source(&error).is_none());
        }
        for error in [
            CliError::from("message"),
            CliError::from(String::from("message")),
        ] {
            assert_eq!(error.exit_code(), 1);
            assert_eq!(error.to_string(), "message");
        }
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission refused");
        let error = CliError::from(io);
        assert_eq!(error.exit_code(), 1);
        assert_eq!(error.to_string(), "permission refused");
    }
}
