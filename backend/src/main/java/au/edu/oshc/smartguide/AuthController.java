package au.edu.oshc.smartguide;

import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api/auth")
class AuthController {

    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");

    private static final Pattern STRONG_PASSWORD_PATTERN =
            Pattern.compile("^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[?=.\\*\\[\\]@$!%\\*?&]).{12,}$");

    private static final String PASSWORD_REQUIREMENTS =
            "Password requirements: at least 12 characters (UPPERCASE, lowercase, a number, special characters eg ?=.\\*[@$!%\\*?&]).";

    final UserRepository users;
    final BCryptPasswordEncoder enc;
    final MfaService mfa;
    final PasswordResetTokenRepository resetTokens;
    final PasswordResetService resetService;
    final ProgressRepository progress;
    final TokenizationService tokens;

    AuthController(
            UserRepository u,
            BCryptPasswordEncoder e,
            MfaService m,
            PasswordResetTokenRepository rt,
            PasswordResetService rs,
            ProgressRepository pr,
            TokenizationService t) {
        users = u;
        enc = e;
        mfa = m;
        resetTokens = rt;
        resetService = rs;
        progress = pr;
        tokens = t;
    }

    static String passwordRequirements() {
        return PASSWORD_REQUIREMENTS;
    }

    static boolean isStrongPassword(String password) {
        return password != null && STRONG_PASSWORD_PATTERN.matcher(password).matches();
    }

    @PostMapping("/register")
    @org.springframework.transaction.annotation.Transactional
    ResponseEntity<?> register(
            @RequestBody Map<String, String> b,
            HttpSession s) {

        String e = b.getOrDefault("email", "").trim().toLowerCase();
        String p = b.getOrDefault("password", "");

        if (!EMAIL_PATTERN.matcher(e).matches()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("message", "Please enter a valid email address."));
        }

        if (!isStrongPassword(p)) {
            return ResponseEntity.badRequest()
                    .body(Map.of("message", passwordRequirements()));
        }

        if (users.findByEmail(e).isPresent()) {
            return ResponseEntity.status(409)
                    .body(Map.of("message", "Account already exists."));
        }

        String mfaSecret = mfa.secret();

        User u = new User();
        u.setEmail(e);
        u.setPasswordHash(enc.encode(p));
        u.setMfaSecret(mfaSecret);
        u.setMfaEnabled(false);
        u.setFullName("OSHC Student");
        u.setRole("STUDENT");

        users.save(u);

        // Tokenise sensitive values after the user has been assigned an ID.
        u.setMfaSecret(tokens.tokenize(e, "mfaSecret", mfaSecret));
        u.setFullName(tokens.tokenize(e, "fullName", "OSHC Student"));
        users.save(u);

        s.setAttribute("PENDING", e);

        return ResponseEntity.ok(
                Map.of("otpauthUri", mfa.uri(e, mfaSecret)));
    }

    @PostMapping("/login")
    ResponseEntity<?> login(
            @RequestBody Map<String, String> b,
            HttpSession s) {

        String e = b.getOrDefault("email", "").trim().toLowerCase();
        String p = b.getOrDefault("password", "");

        User u = users.findByEmail(e).orElse(null);

        if (u == null || !enc.matches(p, u.getPasswordHash())) {
            return ResponseEntity.status(401)
                    .body(Map.of("message", "Invalid credentials."));
        }

        if (!u.isMfaEnabled()) {
            s.setAttribute("AUTH", e);
            s.removeAttribute("PENDING");
            s.setMaxInactiveInterval(60 * 60);

            return ResponseEntity.ok(Map.of(
                    "authenticated", true,
                    "mfaRequired", false,
                    "email", e,
                    "role", u.getRole()));
        }

        s.setAttribute("PENDING", e);
        s.removeAttribute("AUTH");

        return ResponseEntity.ok(Map.of(
                "authenticated", false,
                "mfaRequired", true));
    }

    @PostMapping("/mfa/verify")
    ResponseEntity<?> verify(
            @RequestBody Map<String, String> b,
            HttpSession s) {

        String e = (String) s.getAttribute("PENDING");

        if (e == null) {
            return ResponseEntity.status(401)
                    .body(Map.of(
                            "message",
                            "No pending authentication. Please sign in again."));
        }

        User u = users.findByEmail(e).orElseThrow();
        String secret = tokens.detokenize(e, "mfaSecret", u.getMfaSecret());

        if (!mfa.valid(secret, b.getOrDefault("code", ""))) {
            return ResponseEntity.status(401)
                    .body(Map.of("message", "Invalid authenticator code."));
        }

        u.setMfaEnabled(true);
        users.save(u);

        s.setAttribute("AUTH", e);
        s.removeAttribute("PENDING");
        s.setMaxInactiveInterval(60 * 60);

        return ResponseEntity.ok(Map.of(
                "authenticated", true,
                "email", e,
                "role", u.getRole()));
    }

    @GetMapping("/me")
    ResponseEntity<?> me(HttpSession s) {

        String e = (String) s.getAttribute("AUTH");

        if (e == null) {
            return ResponseEntity.status(401)
                    .body(Map.of("authenticated", false));
        }

        User u = users.findByEmail(e).orElse(null);

        if (u == null) {
            s.invalidate();
            return ResponseEntity.status(401)
                    .body(Map.of("authenticated", false));
        }

        return ResponseEntity.ok(Map.of(
                "authenticated", true,
                "email", e,
                "role", u.getRole(),
                "fullName", tokens.detokenize(e, "fullName", u.getFullName()),
                "mfaEnabled", u.isMfaEnabled()));
    }

    @PostMapping("/forgot-password")
    ResponseEntity<?> forgotPassword(
            @RequestBody Map<String, String> b) {

        String e = b.getOrDefault("email", "").trim().toLowerCase();

        if (EMAIL_PATTERN.matcher(e).matches()) {
            User u = users.findByEmail(e).orElse(null);

            if (u != null) {
                try {
                    String token = resetService.createToken(e);
                    resetService.send(e, token);
                } catch (IllegalStateException ex) {
                    return ResponseEntity.status(503)
                            .body(Map.of("message", ex.getMessage()));
                }
            }
        }

        return ResponseEntity.ok(Map.of(
                "message",
                "If an account exists for that email, a password reset link has been sent."));
    }

    @PostMapping("/reset-password")
    ResponseEntity<?> resetPassword(
            @RequestBody Map<String, String> b) {

        String resetPasswordKey = b.getOrDefault("ResetPasswordKey", "");
        String np = b.getOrDefault("newPassword", "");

        if (!isStrongPassword(np)) {
            return ResponseEntity.badRequest()
                    .body(Map.of("message", passwordRequirements()));
        }

        PasswordResetToken t = resetTokens.findByToken(resetPasswordKey).orElse(null);

        if (t == null || t.getExpiresAt() < System.currentTimeMillis()) {
            return ResponseEntity.badRequest()
                    .body(Map.of(
                            "message",
                            "This password reset link is invalid or has expired."));
        }

        User u = users.findByEmail(t.getEmail()).orElse(null);

        if (u == null) {
            return ResponseEntity.badRequest()
                    .body(Map.of(
                            "message",
                            "This password reset link is invalid or has expired."));
        }

        u.setPasswordHash(enc.encode(np));
        users.save(u);
        resetTokens.delete(t);

        return ResponseEntity.ok(Map.of(
                "message",
                "Password reset successfully. You can now sign in with your new password."));
    }

    @PostMapping("/logout")
    ResponseEntity<?> logout(HttpSession s) {
        s.invalidate();
        return ResponseEntity.noContent().build();
    }
}