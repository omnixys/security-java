package com.omnixys.security.jwe;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.List;

public class JweService {

    private final List<SecretKey> keys;

    public JweService(List<byte[]> keyBytes) {
        if (keyBytes == null || keyBytes.isEmpty()) {
            throw new IllegalArgumentException("At least one JWE key must be provided");
        }
        this.keys = keyBytes.stream()
                .map(bytes -> (SecretKey) new SecretKeySpec(bytes, "AES"))
                .toList();
    }

    public String encrypt(String payload) {
        try {
            SecretKey activeKey = keys.getFirst();
            JWEObject jwe = new JWEObject(
                    new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM)
                            .keyID("key-0")
                            .build(),
                    new Payload(payload)
            );
            jwe.encrypt(new DirectEncrypter(activeKey));
            return jwe.serialize();
        } catch (Exception e) {
            throw new RuntimeException("JWE encryption failed", e);
        }
    }

    public String decrypt(String token) {
        for (SecretKey key : keys) {
            try {
                JWEObject jwe = JWEObject.parse(token);
                jwe.decrypt(new DirectDecrypter(key));
                return jwe.getPayload().toString();
            } catch (Exception ignored) {
            }
        }
        throw new RuntimeException("Unable to decrypt JWE token with any key");
    }
}
