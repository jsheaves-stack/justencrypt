use thiserror::Error;

#[derive(Error, Debug)]
pub enum RequestError {
    #[error("Failed to find session id")]
    MissingSessionId,

    #[error("Failed to find an active session for this session id")]
    MissingActiveSession,

    #[error("Failed to process data")]
    FailedToProcessData,

    #[error("Failed to write data")]
    FailedToWriteData,

    #[error("Failed to create user session")]
    FailedToCreateUserSession,

    #[error("User already exists")]
    UserAlreadyExists,

    #[error("Unsupported file type")]
    UnsupportedFileType,

    #[error("Failed to remove file")]
    FailedToRemoveFile,

    #[error("Failed to add file")]
    FailedToAddFile,

    #[error("Failed to create folder")]
    FailedToCreateFolder,

    #[error("Failed to read folder contents")]
    FailedToReadFolderContents,
}
