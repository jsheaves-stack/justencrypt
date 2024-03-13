use crate::enums::{request_error::RequestError, request_success::RequestSuccess};
use rocket::{
    http::Status,
    response::{Responder, Response, Result},
    Request,
};
use std::io::Cursor;

impl<'r> Responder<'r, 'static> for RequestError {
    fn respond_to(self, _: &'r Request<'_>) -> Result<'static> {
        // Here you map your error enum variants to appropriate HTTP responses.
        let response = match self {
            RequestError::MissingSessionId => Response::build()
                .status(Status::BadRequest)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::MissingActiveSession => Response::build()
                .status(Status::NotFound)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::FailedToProcessData => Response::build()
                .status(Status::InternalServerError)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::FailedToWriteData => Response::build()
                .status(Status::InternalServerError)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::FailedToWriteUserManifest => Response::build()
                .status(Status::InternalServerError)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::FailedToReadUserManifest => Response::build()
                .status(Status::InternalServerError)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::FailedToCreateUserSession => Response::build()
                .status(Status::NotFound)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::UserAlreadyExists => Response::build()
                .status(Status::Conflict)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),

            RequestError::UserDoesNotExist => Response::build()
                .status(Status::NotFound)
                .sized_body(self.to_string().len(), Cursor::new(self.to_string()))
                .ok(),
        };

        response
    }
}

impl<'r> Responder<'r, 'static> for RequestSuccess {
    fn respond_to(self, _: &'r Request<'_>) -> Result<'static> {
        let response = match self {
            RequestSuccess::Created => Response::build().status(Status::Created).ok(),
            RequestSuccess::NoContent => Response::build().status(Status::NoContent).ok(),
        };

        response
    }
}
