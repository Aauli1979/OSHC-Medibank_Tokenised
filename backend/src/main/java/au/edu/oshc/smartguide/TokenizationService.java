package au.edu.oshc.smartguide;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

@Service
class TokenizationService {

    private static final String PREFIX = "tok_";
    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH = 128;

    private final DataTokenRepository repository;
    private final SecretKeySpec key;
    private final SecureRandom random = new SecureRandom();

    TokenizationService(
            DataTokenRepository repository,
            @Value("${app.tokenization-key:change-this-development-key}") String configuredKey) {
        this.repository = repository;
        this.key = new SecretKeySpec(sha256(configuredKey), "AES");
    }

    public String tokenize(String ownerEmail, String fieldName, String plaintext) {
        if (plaintext == null || plaintext.isEmpty()) {
            return "";
        }

        String token = PREFIX + UUID.randomUUID().toString();
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH, iv));
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            DataToken data = new DataToken();
            data.setToken(token);
            data.setOwnerEmail(ownerEmail);
            data.setFieldName(fieldName);
            data.setCiphertext(Base64.getEncoder().encodeToString(iv) + "."
                    + Base64.getEncoder().encodeToString(encrypted));

            repository.save(data);
            return token;
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to protect sensitive profile data.", ex);
        }
    }

    public String detokenize(String ownerEmail, String fieldName, String value) {
        if (value == null || value.isEmpty() || !value.startsWith(PREFIX)) {
            // Backward compatibility with older prototype records.
            return value == null ? "" : value;
        }

        Optional<DataToken> record = repository.findByTokenAndOwnerEmailAndFieldName(
                value, ownerEmail, fieldName);

        if (record.isEmpty()) {
            return "";
        }

        try {
            String[] parts = record.get().getCiphertext().split("\\.", 2);
            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] encrypted = Base64.getDecoder().decode(parts[1]);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH, iv));
            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to recover protected profile data.", ex);
        }
    }

    // This is the entry point the controllers call for profile fields and the
    // MFA secret. It must be @Transactional AND public: the delete of the old
    // token row and the insert of the new one have to happen in a single
    // transaction, and Spring's proxy-based @Transactional only intercepts
    // public methods -- without both of these, the "remove" call below can
    // run with no active EntityManager transaction and throw
    // TransactionRequiredException.
    @Transactional
    public String replace(String ownerEmail, String fieldName, String oldValue, String plaintext) {
        deleteToken(oldValue);
        return tokenize(ownerEmail, fieldName, plaintext);
    }

    public void deleteToken(String value) {
        if (value != null && value.startsWith(PREFIX)) {
            repository.deleteByToken(value);
        }
    }

    @Transactional
    public void deleteForOwner(String ownerEmail) {
        repository.deleteByOwnerEmail(ownerEmail);
    }

    @Transactional
    public void changeOwnerEmail(String oldEmail, String newEmail) {
        repository.updateOwnerEmail(oldEmail, newEmail);
    }

    private static byte[] sha256(String input) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to initialise tokenization.", ex);
        }
    }
}