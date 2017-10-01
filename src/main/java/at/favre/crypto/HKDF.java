package at.favre.crypto;

import javax.crypto.Mac;
import java.io.ByteArrayOutputStream;


/**
 * A standards-compliant implementation of RFC 5869
 * for HMAC-based Key Derivation Function.
 * <p>
 * HKDF follows the "extract-then-expand" paradigm, where the KDF
 * logically consists of two modules.  The first stage takes the input
 * keying material and "extracts" from it a fixed-length pseudorandom
 * key K.  The second stage "expands" the key K into several additional
 * pseudorandom keys (the output of the KDF).
 * <p>
 * HKDF was first described by Hugo Krawczyk.
 * <p>
 * This implementation is thread safe without the need for synchronization.
 * <p>
 * Simple Example:
 *
 * <pre>
 *     byte[] pseudoRandomKey = HKDF.fromHmacSha256().extract(lowEntropyInput, null);
 *     byte[] outputKeyingMaterial = HKDF.fromHmacSha256().expand(pseudoRandomKey, null, 64);
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc5869">RFC 5869</a>
 * @see <a href="https://eprint.iacr.org/2010/264.pdf">Cryptographic Extraction and Key Derivation:
 * The HKDF Scheme</a>
 * @see <a href="https://en.wikipedia.org/wiki/HKDF">Wikipedia: HKDF</a>
 */
public final class HKDF {
    /**
     * Cache instances
     */
    private static HKDF hkdfHmacSha256;
    private static HKDF hkdfHmacSha512;

    private final HkdfMacFactory macFactory;

    private HKDF(HkdfMacFactory macFactory) {
        this.macFactory = macFactory;
    }

    /**
     * Return a shared instance using HMAC with Sha256.
     * Even thou shared, this instance is thread-safe.
     *
     * @return HKDF instance
     */
    public static HKDF fromHmacSha256() {
        if (hkdfHmacSha256 == null) {
            hkdfHmacSha256 = from(HkdfMacFactory.Default.hmacSha256());
        }
        return hkdfHmacSha256;
    }

    /**
     * Return a shared instance using HMAC with Sha512.
     * Even thou shared, this instance is thread-safe.
     *
     * @return HKDF instance
     */
    public static HKDF fromHmacSha512() {
        if (hkdfHmacSha512 == null) {
            hkdfHmacSha512 = from(HkdfMacFactory.Default.hmacSha512());
        }
        return hkdfHmacSha512;
    }

    /**
     * Create a new HKDF instance for given macFactory.
     *
     * @param macFactory used for HKDF
     * @return a new instance of HKDF
     */
    public static HKDF from(HkdfMacFactory macFactory) {
        return new HKDF(macFactory);
    }

    /**
     * <strong>Step 1 of RFC 5869 (Section 2.2)</strong>
     * <p>
     * The first stage takes the input keying material and "extracts" from it a fixed-length pseudorandom
     * key K. The goal of the "extract" stage is to "concentrate" and provide a more uniformly unbiased and higher entropy but smaller output.
     * This is done by utilising the diffusion properties of cryptographic MACs.
     * <p>
     * <strong>About Salts (from RFC 5869):</strong>
     *
     * <blockquote>
     * HKDF is defined to operate with and without random salt.  This is
     * done to accommodate applications where a salt value is not available.
     * We stress, however, that the use of salt adds significantly to the
     * strength of HKDF, ensuring independence between different uses of the
     * hash function, supporting "source-independent" extraction, and
     * strengthening the analytical results that back the HKDF design.
     * </blockquote>
     *
     * @param inputKeyingMaterial data to be extracted (IKM)
     * @param salt                optional salt value (a non-secret random value);
     *                            if not provided, it is set to a array of hash length of zeros.
     * @return a new byte array pseudorandom key (of hash length in bytes) (PRK) which can be used to expand
     * @see <a href="https://tools.ietf.org/html/rfc5869#section-2.2">RFC 5869 Section 2.2</a>
     */
    public byte[] extract(byte[] inputKeyingMaterial, byte[] salt) {
        return new Extractor(macFactory).execute(inputKeyingMaterial, salt);
    }

    /**
     * <strong>Step 1 of RFC 5869 (Section 2.3)</strong>
     * <p>
     * To "expand" the generated output of an already reasonably random input such as an existing shared key into a larger
     * cryptographically independent output, thereby producing multiple keys deterministically from that initial shared key,
     * so that the same process may produce those same secret keys safely on multiple devices, as long as the same inputs
     * are utilised.
     * <p>
     * <strong>About Info (from RFC 5869):</strong>
     *
     * <blockquote>
     * While the 'info' value is optional in the definition of HKDF, it is
     * often of great importance in applications.  Its main objective is to
     * bind the derived key material to application- and context-specific
     * information.  For example, 'info' may contain a protocol number,
     * algorithm identifiers, user identities, etc.  In particular, it may
     * prevent the derivation of the same keying material for different
     * contexts (when the same input key material (IKM) is used in such
     * different contexts).
     * </blockquote>
     *
     * @param pseudoRandomKey a pseudorandom key of at least hmac hash length in bytes (usually, the output from the extract step)
     * @param info            optional context and application specific information; may be null
     * @param outLengthBytes  length of output keying material in bytes
     * @return new byte array of output keying material (OKM)
     * @see <a href="https://tools.ietf.org/html/rfc5869#section-2.3">RFC 5869 Section 2.3</a>
     */
    public byte[] expand(byte[] pseudoRandomKey, byte[] info, int outLengthBytes) {
        return new Expander(macFactory).execute(pseudoRandomKey, info, outLengthBytes);
    }

    /**
     * Convenience method for extract &amp; expand in a single method
     *
     * @param inputKeyingMaterial data to be extracted (IKM)
     * @param saltExtract         optional salt value (a non-secret random value);
     * @param infoExpand          optional context and application specific information; may be null
     * @param outLengthByte       length of output keying material in bytes
     * @return new byte array of output keying material (OKM)
     */
    public byte[] extractAndExpand(byte[] inputKeyingMaterial, byte[] saltExtract, byte[] infoExpand, int outLengthByte) {
        return new Expander(macFactory).execute(new Extractor(macFactory).execute(inputKeyingMaterial, saltExtract), infoExpand, outLengthByte);
    }

    /**
     * Get the used mac factory
     *
     * @return factory
     */
    HkdfMacFactory getMacFactory() {
        return macFactory;
    }

    /* ************************************************************************** IMPL */

    static final class Extractor {
        private final HkdfMacFactory macFactory;

        Extractor(HkdfMacFactory macFactory) {
            this.macFactory = macFactory;
        }

        /**
         * Step 1 of RFC 5869
         * <p>
         * The first stage takes the input keying material and "extracts" from it a fixed-length pseudorandom
         * key K. The goal of the "extract" stage is to "concentrate" the possibly dispersed entropy of the input
         * keying material into a short, but cryptographically strong, pseudorandom key.
         *
         * @param inputKeyingMaterial data to be extracted (IKM)
         * @param salt                optional salt value (a non-secret random value);
         *                            if not provided, it is set to a array of hash length of zeros.
         * @return a new byte array pseudorandom key (of hash length in bytes) (PRK) which can be used to expand
         */
        byte[] execute(byte[] inputKeyingMaterial, byte[] salt) {
            if (salt == null || salt.length == 0) {
                salt = new byte[macFactory.macHashLengthByte()];
            }

            if (inputKeyingMaterial == null || inputKeyingMaterial.length <= 0) {
                throw new IllegalArgumentException("provided inputKeyingMaterial must be at least of size 1 and not null");
            }

            Mac mac = macFactory.createMacInstance(salt);
            mac.update(inputKeyingMaterial);
            return mac.doFinal();
        }
    }

    static final class Expander {
        private final HkdfMacFactory macFactory;

        Expander(HkdfMacFactory macFactory) {
            this.macFactory = macFactory;
        }

        /**
         * Step 2 of RFC 5869.
         * <p>
         * The second stage "expands" the pseudorandom key to the desired
         * length; the number and lengths of the output keys depend on the
         * specific cryptographic algorithms for which the keys are needed.
         *
         * @param pseudoRandomKey a pseudorandom key of at least hmac hash length in bytes (usually, the output from the extract step)
         * @param info            optional context and application specific information; may be null
         * @param outLengthBytes  length of output keying material in bytes (must be <= 255 * mac hash length)
         * @return new byte array of output keying material (OKM)
         */
        byte[] execute(byte[] pseudoRandomKey, byte[] info, int outLengthBytes) {

            if (outLengthBytes <= 0) {
                throw new IllegalArgumentException("out length bytes must be at least 1");
            }

            if (pseudoRandomKey == null || pseudoRandomKey.length <= 0) {
                throw new IllegalArgumentException("provided pseudoRandomKey must be at least of size 1 and not null");
            }

            Mac hmacHasher = macFactory.createMacInstance(pseudoRandomKey);

            if (info == null) {
                info = new byte[0];
            }

            byte[] blockN = new byte[0];

            int iterations = (int) Math.ceil(((double) outLengthBytes) / ((double) macFactory.macHashLengthByte()));

            if (iterations > 255) {
                throw new IllegalArgumentException("out length must be maximal 255 * hash len");
            }

            ByteArrayOutputStream stream = new ByteArrayOutputStream(outLengthBytes);
            int remainingBytes = outLengthBytes;

            for (int i = 0; i < iterations; i++) {
                hmacHasher.update(blockN);
                hmacHasher.update(info);
                hmacHasher.update((byte) (i + 1));

                blockN = hmacHasher.doFinal();

                int stepSize = Math.min(remainingBytes, blockN.length);

                stream.write(blockN, 0, stepSize);
                remainingBytes -= stepSize;
            }

            return stream.toByteArray();
        }
    }
}