/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is Android Sync Client.
 *
 * The Initial Developer of the Original Code is
 * the Mozilla Foundation.
 * Portions created by the Initial Developer are Copyright (C) 2011
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 * Jason Voll
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

package at.favre.crypto;

import at.favre.util.Bytes;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.Key;
import java.util.Arrays;


/**
 * A standards-compliant implementation of RFC 5869
 * for HMAC-based Key Derivation Function.
 * HMAC uses HMAC SHA256 standard.
 * <p>
 * See: https://github.com/mozilla-services/sync-crypto/blob/master/src/main/java/org/mozilla/android/sync/crypto/HKDF.java
 */
public final class HKDF {
    private static final int BLOCKSIZE = 256 / 8;

    private HKDF() {
    }

    /**
     * Step 1 of RFC 5869
     * Get sha256HMAC Bytes
     * Input: salt (message), IKM (input keyring material)
     * Output: PRK (pseudorandom key)
     */
    public static byte[] hkdfExtract(byte[] salt, byte[] IKM) {
        return digestBytes(IKM, makeHMACHasher(salt));
    }

    /**
     * Step 2 of RFC 5869.
     * Input: PRK from step 1, info, length.
     * Output: OKM (output keyring material).
     */
    public static byte[] hkdfExpand(byte[] prk, byte[] info, int lenBytes) {

        Mac hmacHasher = makeHMACHasher(prk);

        byte[] T = {};
        byte[] Tn = {};

        int iterations = (int) Math.ceil(((double) lenBytes) / ((double) BLOCKSIZE));
        for (int i = 0; i < iterations; i++) {
            Tn = digestBytes(Bytes.concat(Tn, info, ByteBuffer.allocate(4).putInt(i + 1).array()), hmacHasher);
            T = Bytes.concat(T, Tn);
        }

        return Arrays.copyOfRange(T, 0, lenBytes);
    }

    /**
     * Make HMAC key
     * Input: key (salt)
     * Output: Key HMAC-Key
     */
    private static Key makeHMACKey(byte[] key) {
        if (key.length == 0) {
            key = new byte[BLOCKSIZE];
        }
        return new SecretKeySpec(key, "HmacSHA256");
    }

    /**
     * Make an HMAC hasher
     * Input: Key hmacKey
     * Ouput: An HMAC Hasher
     */
    private static Mac makeHMACHasher(byte[] key) {
        try {
            Mac hmacHasher = Mac.getInstance("hmacSHA256");
            hmacHasher.init(makeHMACKey(key));
            return hmacHasher;
        } catch (Exception e) {
            throw new IllegalStateException("could not make hmac hasher in hkdf", e);
        }
    }

    /**
     * Hash bytes with given hasher
     * Input: message to hash, HMAC hasher
     * Output: hashed byte[].
     */
    private static byte[] digestBytes(byte[] message, Mac hasher) {
        hasher.update(message);
        byte[] ret = hasher.doFinal();
        hasher.reset();
        return ret;
    }

    /**
     * Extract and expand in one call
     *
     * @param ikm
     * @param saltExtract
     * @param outLengthByte
     * @return hashed
     */
    public static byte[] hkdf(byte[] ikm, byte[] saltExtract, byte[] saltExpand, int outLengthByte) {
        byte[] pkr = hkdfExtract(saltExtract, ikm);
        return hkdfExpand(pkr, saltExpand, outLengthByte);
    }
}