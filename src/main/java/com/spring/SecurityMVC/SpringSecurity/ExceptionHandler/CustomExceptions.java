package com.spring.SecurityMVC.SpringSecurity.ExceptionHandler;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.dao.DataAccessException;

public class CustomExceptions {

    // 400 Bad Request - 잘못된 요청
    public static class InvalidRequestException extends IllegalArgumentException {
        public InvalidRequestException(String message) {
            super(message);
        }
    }

    public static class MissingRequestBodyException extends IllegalArgumentException {
        public MissingRequestBodyException(String message) {
            super(message);
        }
    }

    public static class InvalidParameterException extends IllegalArgumentException {
        public InvalidParameterException(String message) {
            super(message);
        }
    }

    // 401 Unauthorized - 인증 실패
    public static class AuthenticationFailedException extends AuthenticationException {
        public AuthenticationFailedException(String message) {
            super(message);
        }
    }

    public static class TokenException extends AuthenticationException {
        public TokenException(String message) {
            super(message);
        }
    }

    public static class SessionException extends AuthenticationException {
        public SessionException(String message) {
            super(message);
        }
    }

    // 403 Forbidden - 접근 권한 거부
    public static class EmailCodeMismatchException extends AccessDeniedException {
        public EmailCodeMismatchException(String message) {
            super(message);
        }
    }

    public static class InvalidIpException extends AccessDeniedException {
        public InvalidIpException(String message) {
            super(message);
        }
    }

    public static class InsufficientRoleException extends AccessDeniedException {
        public InsufficientRoleException(String message) {
            super(message);
        }
    }

    // 404 Not Found - 리소스 찾을 수 없음
    public static class ResourceNotFoundException extends RuntimeException {
        public ResourceNotFoundException(String message) {
            super(message);
        }
    }

    // 409 Conflict - 충돌
    public static class UserAlreadyExistsException extends IllegalStateException {
        public UserAlreadyExistsException(String message) {
            super(message);
        }
    }

    public static class DataConflictException extends IllegalStateException {
        public DataConflictException(String message) {
            super(message);
        }
    }

    // 500 Internal Server Error - 서버 오류
    public static class LogoutFailedException extends RuntimeException {
        public LogoutFailedException(String message) {
            super(message);
        }
    }

    public static class DatabaseException extends DataAccessException {
        public DatabaseException(String message) {
            super(message);
        }
    }



    public static class ExternalServiceException extends RuntimeException {
        public ExternalServiceException(String message) {
            super(message);
        }
    }

    // 502 Bad Gateway - 외부 서비스 연결 실패
    public static class BadGatewayException extends RuntimeException {
        public BadGatewayException(String message) {
            super(message);
        }
    }

    // 503 Service Unavailable - 서비스 이용 불가
    public static class ServiceUnavailableException extends RuntimeException {
        public ServiceUnavailableException(String message) {
            super(message);
        }
    }
    public static class EmailServiceException extends RuntimeException {
        public EmailServiceException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
