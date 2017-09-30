package at.favre.crypto;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

/**
 * Factory class for creating {@link Mac} hashers
 */
interface HkdfMacFactory {

    /**
     * Creates a new instance of Hmac with given key
     *
     * @param key the key used, must not be null
     * @return a new mac instance
     */
    Mac createMacInstance(byte[] key);

    /**
     * The hash length size of used mac in bytes (e.g. HmacSha256 has a hash length size of 32)
     *
     * @return output hash byte size
     */
    int macHashLengthByte();

    /**
     * Default implementation
     */
    class Default implements HkdfMacFactory {
        private final String macAlgorithmName;
        private final int hashLengthBytes;

        public static HkdfMacFactory hmacSha256() {
            return new Default("HmacSHA256", 256 / 8);
        }

        public static HkdfMacFactory hmacSha512() {
            return new Default("HmacSHA512", 512 / 8);
        }

        Default(String macAlgorithmName, int hashLengthBytes) {
            this.macAlgorithmName = macAlgorithmName;
            this.hashLengthBytes = hashLengthBytes;
        }

        @Override
        public Mac createMacInstance(byte[] key) {
            try {
                SecretKey secretKey = new SecretKeySpec(key, macAlgorithmName);
                Mac hmacHasher = Mac.getInstance(macAlgorithmName);
                hmacHasher.init(secretKey);
                return hmacHasher;
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("defined mac algorithm was not found", e);
            } catch (Exception e) {
                throw new IllegalStateException("could not make hmac hasher in hkdf", e);
            }
        }

        @Override
        public int macHashLengthByte() {
            return hashLengthBytes;
        }
    }
}
