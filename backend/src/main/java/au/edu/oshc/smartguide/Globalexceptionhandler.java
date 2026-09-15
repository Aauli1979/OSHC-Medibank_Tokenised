package au.edu.oshc.smartguide;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/**
 * Ensures unhandled backend errors are logged with a full stack trace and
 * return a JSON body with a real "message" field instead of Spring's blank
 * default error page. This makes future issues visible in the UI instead of
 * a generic "Request failed (500)".
 */
@RestControllerAdvice
class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(Exception.class)
    ResponseEntity<?> handleUnexpected(Exception ex) {
        log.error("Unhandled error while processing request", ex);

        // TEMPORARY (debugging): surface the real exception type/message so it
        // shows up in the UI instead of a generic "Request failed (500)".
        // Revert this to a generic message before shipping to real users --
        // stack details should not normally be exposed to the client.
        Throwable root = ex;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of(
                        "message",
                        "Server error: " + root.getClass().getSimpleName()
                                + (root.getMessage() != null ? " - " + root.getMessage() : "")));
    }
}