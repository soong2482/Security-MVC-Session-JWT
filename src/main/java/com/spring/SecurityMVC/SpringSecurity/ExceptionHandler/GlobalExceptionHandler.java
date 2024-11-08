package com.spring.SecurityMVC.SpringSecurity.ExceptionHandler;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.servlet.NoHandlerFoundException;


@ControllerAdvice
public class GlobalExceptionHandler {

    // 400 Bad Request - 잘못된 요청
    @ExceptionHandler(CustomExceptions.InvalidRequestException.class)
    public ResponseEntity<String> handleInvalidRequestException(CustomExceptions.InvalidRequestException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
    }

    @ExceptionHandler(CustomExceptions.MissingRequestBodyException.class)
    public ResponseEntity<String> handleMissingRequestBodyException(CustomExceptions.MissingRequestBodyException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
    }

    @ExceptionHandler(CustomExceptions.InvalidParameterException.class)
    public ResponseEntity<String> handleInvalidParameterException(CustomExceptions.InvalidParameterException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<String> handleHttpMessageNotReadableException(HttpMessageNotReadableException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Request body is missing or invalid");
    }

    // 401 Unauthorized - 인증 실패
    @ExceptionHandler(CustomExceptions.AuthenticationFailedException.class)
    public ResponseEntity<String> handleAuthenticationFailedException(CustomExceptions.AuthenticationFailedException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ex.getMessage());
    }

    @ExceptionHandler(CustomExceptions.TokenException.class)
    public ResponseEntity<String> handleTokenException(CustomExceptions.TokenException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ex.getMessage());
    }

    @ExceptionHandler(CustomExceptions.SessionException.class)
    public ResponseEntity<String> handleSessionException(CustomExceptions.SessionException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ex.getMessage());
    }

    // 403 Forbidden - 접근 권한 거부
    @ExceptionHandler(CustomExceptions.EmailCodeMismatchException.class)
    public ResponseEntity<String> handleEmailCodeMismatchException(CustomExceptions.EmailCodeMismatchException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
    }

    @ExceptionHandler(CustomExceptions.InvalidIpException.class)
    public ResponseEntity<String> handleInvalidIpException(CustomExceptions.InvalidIpException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
    }

    @ExceptionHandler(CustomExceptions.InsufficientRoleException.class)
    public ResponseEntity<String> handleInsufficientRoleException(CustomExceptions.InsufficientRoleException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
    }

    // 404 Not Found - 리소스 찾을 수 없음
    @ExceptionHandler(CustomExceptions.ResourceNotFoundException.class)
    public ResponseEntity<String> handleResourceNotFoundException(CustomExceptions.ResourceNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ex.getMessage());
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<String> handleNoHandlerFoundException(NoHandlerFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body("404 Not Found: The requested resource was not found.");
    }

    // 409 Conflict - 충돌
    @ExceptionHandler(CustomExceptions.UserAlreadyExistsException.class)
    public ResponseEntity<String> handleUserAlreadyExistsException(CustomExceptions.UserAlreadyExistsException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(ex.getMessage());
    }

    @ExceptionHandler(CustomExceptions.DataConflictException.class)
    public ResponseEntity<String> handleDataConflictException(CustomExceptions.DataConflictException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(ex.getMessage());
    }

    // 500 Internal Server Error - 서버 오류
    @ExceptionHandler(CustomExceptions.LogoutFailedException.class)
    public ResponseEntity<String> handleLogoutFailedException(CustomExceptions.LogoutFailedException ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ex.getMessage());
    }

    @ExceptionHandler(CustomExceptions.DatabaseException.class)
    public ResponseEntity<String> handleDatabaseException(CustomExceptions.DatabaseException ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Database error: " + ex.getMessage());
    }

    @ExceptionHandler(CustomExceptions.ExternalServiceException.class)
    public ResponseEntity<String> handleExternalServiceException(CustomExceptions.ExternalServiceException ex) {
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body("External service error: " + ex.getMessage());
    }

    @ExceptionHandler(CustomExceptions.BadGatewayException.class)
    public ResponseEntity<String> handleBadGatewayException(CustomExceptions.BadGatewayException ex) {
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(ex.getMessage());
    }

    @ExceptionHandler(CustomExceptions.ServiceUnavailableException.class)
    public ResponseEntity<String> handleServiceUnavailableException(CustomExceptions.ServiceUnavailableException ex) {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(ex.getMessage());
    }

    // 모든 기타 예외에 대한 일반 처리
    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleGeneralException(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An unexpected error occurred: " + ex.getMessage());
    }
}
