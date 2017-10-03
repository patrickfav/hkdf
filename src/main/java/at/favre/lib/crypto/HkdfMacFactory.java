package at.favre.lib.crypto;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/**
 * Factory class for creating {@link Mac} hashers
 */
interface HkdfMacFactory {

    /**
     * Creates a new instance of Hmac with given key, i.e. it must already be initialized
     * with {@link Mac#init(Key)}.
     *
     * @param key the key used, must not be null
     * @return a new mac instance
     */
    Mac createInstance(byte[] key);

    /**
     * Default implementation
     */
    final class Default implements HkdfMacFactory {
        private final String macAlgorithmName;
        private final int hashLengthBytes;
        private final Provider provider;

        /**
         * Creates a factory creating HMAC with SHA-256
         *
         * @return factory
         */
        public static HkdfMacFactory hmacSha256() {
            return new Default("HmacSHA256", 256 / 8, null);
        }

        /**
         * Creates a factory creating HMAC with SHA-512
         *
         * @return factory
         */
        public static HkdfMacFactory hmacSha512() {
            return new Default("HmacSHA512", 512 / 8, null);
        }

        /**
         * Creates a factory creating HMAC with SHA-1
         *
         * @return factory
         * @deprecated sha1 with HMAC should be fine, but not recommended for new protocols; see https://crypto.stackexchange.com/questions/26510/why-is-hmac-sha1-still-considered-secure
         */
        @Deprecated
        public static HkdfMacFactory hmacSha1() {
            return new Default("HmacSHA1", 160 / 8, null);
        }

        /**
         * Creates a mac factory
         *
         * @param macAlgorithmName as used by {@link Mac#getInstance(String)}
         * @param hashLengthBytes  hash length size of used mac in bytes
         */
        public Default(String macAlgorithmName, int hashLengthBytes) {
            this(macAlgorithmName, hashLengthBytes, null);
        }

        /**
         * Creates a mac factory
         *
         * @param macAlgorithmName as used by {@link Mac#getInstance(String)}
         * @param hashLengthBytes  hash length size of used mac in bytes
         * @param provider         what security provider, see {@link Mac#getInstance(String, Provider)}; may be null to use default
         */
        public Default(String macAlgorithmName, int hashLengthBytes, Provider provider) {
            this.macAlgorithmName = macAlgorithmName;
            this.hashLengthBytes = hashLengthBytes;
            this.provider = provider;
        }

        @Override
        public Mac createInstance(byte[] key) {
            try {
                SecretKey secretKey = new SecretKeySpec(key, macAlgorithmName);

                Mac hmacInstance;

                if (provider == null) {
                    hmacInstance = Mac.getInstance(macAlgorithmName);
                } else {
                    hmacInstance = Mac.getInstance(macAlgorithmName, provider);
                }

                hmacInstance.init(secretKey);
                return hmacInstance;
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("defined mac algorithm was not found", e);
            } catch (Exception e) {
                throw new IllegalStateException("could not make hmac hasher in hkdf", e);
            }
        }
    }
}
