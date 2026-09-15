package au.edu.oshc.smartguide;

import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/profile")
class ProfileController {

    final UserRepository users;
    final BCryptPasswordEncoder enc;
    final MfaService mfa;
    final ProgressRepository progress;
    final TokenizationService tokens;

    ProfileController(
            UserRepository u,
            BCryptPasswordEncoder e,
            MfaService m,
            ProgressRepository pr,
            TokenizationService t) {
        users = u;
        enc = e;
        mfa = m;
        progress = pr;
        tokens = t;
    }

    User current(HttpSession s) {
        String e = (String) s.getAttribute("AUTH");
        return e == null ? null : users.findByEmail(e).orElse(null);
    }

    ResponseEntity<?> unauthorized() {
        return ResponseEntity.status(401)
                .body(Map.of("message", "Authentication required."));
    }

    Map<String, Object> view(User u) {
        String email = u.getEmail();

        return new LinkedHashMap<>(Map.of(
                "fullName", tokens.detokenize(email, "fullName", u.getFullName()),
                "userId", String.format("OSHC-%06d", u.getId()),
                "address", tokens.detokenize(email, "address", u.getAddress()),
                "birthdate", tokens.detokenize(email, "birthdate", u.getBirthdate()),
                "phoneNumber", tokens.detokenize(email, "phoneNumber", u.getPhoneNumber()),
                "email", email,
                "photoData", tokens.detokenize(email, "photoData", u.getPhotoData()),
                "mfaEnabled", u.isMfaEnabled(),
                "role", Objects.toString(u.getRole(), "STUDENT")
        ));
    }

    @GetMapping
    ResponseEntity<?> get(HttpSession s) {
        User u = current(s);
        return u == null ? unauthorized() : ResponseEntity.ok(view(u));
    }

    @PutMapping
    ResponseEntity<?> update(
            @RequestBody Map<String, Object> b,
            HttpSession s) {

        User u = current(s);
        if (u == null) return unauthorized();

        String email = u.getEmail();

        String fullName = clean(Objects.toString(b.get("fullName"), ""), 100);
        String address = clean(Objects.toString(b.get("address"), ""), 300);
        String birthdate = clean(Objects.toString(b.get("birthdate"), ""), 20);
        String phone = clean(Objects.toString(b.get("phoneNumber"), ""), 40);

        u.setFullName(tokens.replace(
                email, "fullName", u.getFullName(), fullName));

        u.setAddress(tokens.replace(
                email, "address", u.getAddress(), address));

        u.setBirthdate(tokens.replace(
                email, "birthdate", u.getBirthdate(), birthdate));

        u.setPhoneNumber(tokens.replace(
                email, "phoneNumber", u.getPhoneNumber(), phone));

        if (b.containsKey("photoData")) {
            String photo = Objects.toString(b.get("photoData"), "");

            if (photo.length() > 3_000_000) {
                return ResponseEntity.badRequest()
                        .body(Map.of(
                                "message",
                                "Photo is too large. Please use an image under about 2 MB."));
            }

            u.setPhotoData(tokens.replace(
                    email, "photoData", u.getPhotoData(), photo));
        }

        users.save(u);

        return ResponseEntity.ok(view(u));
    }

    @PostMapping("/email")
    @Transactional
    ResponseEntity<?> email(
            @RequestBody Map<String, String> b,
            HttpSession s) {

        User u = current(s);
        if (u == null) return unauthorized();

        String pass = b.getOrDefault("currentPassword", "");
        String email = b.getOrDefault("newEmail", "").trim().toLowerCase();

        if (!enc.matches(pass, u.getPasswordHash())) {
            return ResponseEntity.status(400)
                    .body(Map.of("message", "Current password is incorrect."));
        }

        if (!email.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$")) {
            return ResponseEntity.badRequest()
                    .body(Map.of("message", "Enter a valid email address."));
        }

        if (users.findByEmail(email)
                .filter(x -> !x.getEmail().equals(u.getEmail()))
                .isPresent()) {
            return ResponseEntity.status(409)
                    .body(Map.of("message", "That email is already registered."));
        }

        String oldEmail = u.getEmail();

        u.setEmail(email);
        users.save(u);

        // Keep token ownership aligned with the new account identifier.
        tokens.changeOwnerEmail(oldEmail, email);

        s.setAttribute("AUTH", email);

        return ResponseEntity.ok(view(u));
    }

    @PostMapping("/password")
    ResponseEntity<?> password(
            @RequestBody Map<String, String> b,
            HttpSession s) {

        User u = current(s);
        if (u == null) return unauthorized();

        String old = b.getOrDefault("currentPassword", "");
        String np = b.getOrDefault("newPassword", "");

        if (!enc.matches(old, u.getPasswordHash())) {
            return ResponseEntity.status(400)
                    .body(Map.of("message", "Current password is incorrect."));
        }

        if (!AuthController.isStrongPassword(np)) {
            return ResponseEntity.badRequest()
                    .body(Map.of("message", AuthController.passwordRequirements()));
        }

        u.setPasswordHash(enc.encode(np));
        users.save(u);

        return ResponseEntity.ok(
                Map.of("message", "Password changed successfully."));
    }

    @PostMapping("/mfa/enable")
    ResponseEntity<?> enableMfa(
            @RequestBody Map<String, String> b,
            HttpSession s) {

        User u = current(s);
        if (u == null) return unauthorized();

        if (!enc.matches(
                b.getOrDefault("password", ""),
                u.getPasswordHash())) {
            return ResponseEntity.status(400)
                    .body(Map.of("message", "Password verification failed."));
        }

        String secret = mfa.secret();

        s.setAttribute("MFA_ENABLE_SECRET", secret);
        s.setAttribute("MFA_ENABLE_STARTED_AT", System.currentTimeMillis());

        return ResponseEntity.ok(Map.of(
                "otpauthUri", mfa.uri(u.getEmail(), secret),
                "mfaEnabled", u.isMfaEnabled()));
    }

    @PostMapping("/mfa/enable/verify")
    ResponseEntity<?> verifyEnableMfa(
            @RequestBody Map<String, String> b,
            HttpSession s) {

        User u = current(s);
        if (u == null) return unauthorized();

        String secret = (String) s.getAttribute("MFA_ENABLE_SECRET");
        Long started = (Long) s.getAttribute("MFA_ENABLE_STARTED_AT");

        if (secret == null
                || started == null
                || System.currentTimeMillis() - started > 5 * 60 * 1000L) {
            return ResponseEntity.status(400)
                    .body(Map.of(
                            "message",
                            "MFA setup has expired. Start setup again."));
        }

        if (!mfa.valid(secret, b.getOrDefault("code", ""))) {
            return ResponseEntity.status(400)
                    .body(Map.of("message", "Invalid authenticator code."));
        }

        // Replace any previous MFA secret token.
        u.setMfaSecret(tokens.replace(
                u.getEmail(), "mfaSecret", u.getMfaSecret(), secret));
        u.setMfaEnabled(true);
        users.save(u);

        s.removeAttribute("MFA_ENABLE_SECRET");
        s.removeAttribute("MFA_ENABLE_STARTED_AT");

        return ResponseEntity.ok(Map.of(
                "message", "MFA enabled successfully.",
                "mfaEnabled", true));
    }

    @DeleteMapping
    @Transactional
    ResponseEntity<?> deleteAccount(
            @RequestBody Map<String, String> b,
            HttpSession s) {

        User u = current(s);
        if (u == null) return unauthorized();

        String password = b.getOrDefault("password", "");

        if (!enc.matches(password, u.getPasswordHash())) {
            return ResponseEntity.status(400)
                    .body(Map.of("message", "Password verification failed."));
        }

        String email = u.getEmail();

        /*
         * Delete dependent learning data and tokenised data before
         * deleting the account. This avoids orphaned sensitive data
         * and prevents common foreign-key/delete ordering failures.
         */
        progress.findByEmail(email).ifPresent(progress::delete);
        progress.flush();

        tokens.deleteForOwner(email);

        users.delete(u);
        users.flush();

        s.invalidate();

        return ResponseEntity.ok(
                Map.of("message", "Account deleted successfully."));
    }

    @PostMapping("/mfa/disable")
    ResponseEntity<?> disableMfa(
            @RequestBody Map<String, String> b,
            HttpSession s) {

        User u = current(s);
        if (u == null) return unauthorized();

        if (!enc.matches(
                b.getOrDefault("password", ""),
                u.getPasswordHash())) {
            return ResponseEntity.status(400)
                    .body(Map.of("message", "Password verification failed."));
        }

        u.setMfaEnabled(false);
        users.save(u);

        s.invalidate();

        return ResponseEntity.ok(
                Map.of("message", "MFA disabled. You must sign in again."));
    }

    @PostMapping("/mfa/reset")
    ResponseEntity<?> resetMfa(
            @RequestBody Map<String, String> b,
            HttpSession s) {

        User u = current(s);
        if (u == null) return unauthorized();

        if (!enc.matches(
                b.getOrDefault("password", ""),
                u.getPasswordHash())) {
            return ResponseEntity.status(400)
                    .body(Map.of("message", "Password verification failed."));
        }

        String secret = mfa.secret();

        u.setMfaSecret(tokens.replace(
                u.getEmail(), "mfaSecret", u.getMfaSecret(), secret));

        u.setMfaEnabled(false);
        users.save(u);

        s.setAttribute("PENDING", u.getEmail());
        s.removeAttribute("AUTH");

        return ResponseEntity.ok(
                Map.of("otpauthUri", mfa.uri(u.getEmail(), secret)));
    }

    String clean(String v, int max) {
        if (v == null) return "";
        String x = v.trim();
        return x.substring(0, Math.min(x.length(), max));
    }
}
