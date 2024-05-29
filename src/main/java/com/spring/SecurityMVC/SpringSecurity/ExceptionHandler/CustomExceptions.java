package com.spring.SecurityMVC.SpringSecurity.ExceptionHandler;

public class CustomExceptions {

    public static class InvalidRequestException extends RuntimeException {
        public InvalidRequestException(String message) {
            super(message);
        }
    }

    public static class EmailCodeMismatchException extends RuntimeException {
        public EmailCodeMismatchException(String message) {
            super(message);
        }
    }

    public static class UserAlreadyExistsException extends RuntimeException {
        public UserAlreadyExistsException(String message) {
            super(message);
        }
    }

    public static class MissingRequestBodyException extends RuntimeException {
        public MissingRequestBodyException(String message) {
            super(message);
        }
    }

    public static class AuthenticationFailedException extends RuntimeException {
        public AuthenticationFailedException(String message) {
            super(message);
        }
    }


}
