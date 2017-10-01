package at.favre.crypto;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.RandomUtils;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

public class HKDFTest {
    @Before
    public void setUp() throws Exception {
    }

    @Test
    public void simpleUseCase() throws Exception {
        //if no dynamic salt is available, a static salt is better than null
        byte[] staticSalt32Byte = new byte[]{(byte) 0xDA, (byte) 0xAC, 0x3E, 0x10, 0x55, (byte) 0xB5, (byte) 0xF1, 0x3E, 0x53, (byte) 0xE4, 0x70, (byte) 0xA8, 0x77, 0x79, (byte) 0x8E, 0x0A, (byte) 0x89, (byte) 0xAE, (byte) 0x96, 0x5F, 0x19, 0x5D, 0x53, 0x62, 0x58, (byte) 0x84, 0x2C, 0x09, (byte) 0xAD, 0x6E, 0x20, (byte) 0xD4};

        //example input
        String userInput = "this is a user input with bad entropy";

        //extract the "raw" data to create output with even entropy
        byte[] extracted = HKDF.extractHmacSha256(userInput.getBytes(StandardCharsets.UTF_8), staticSalt32Byte);

        //create expanded bytes for e.g. AES secret key and IV
        byte[] expandedAesKey = HKDF.expandHmacSha256(extracted,
                "AES-Key".getBytes(StandardCharsets.UTF_8), 16);
        byte[] expandedIv = HKDF.expandHmacSha256(extracted,
                "AES-IV".getBytes(StandardCharsets.UTF_8), 12);

        //Example boilerplate encrypting a simple string with created key/iv
        SecretKey key = new SecretKeySpec(expandedAesKey, "AES"); //AES-128 key
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, expandedIv));
        byte[] encrypted = cipher.doFinal("my secret message".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void checkLength() throws Exception {
        int[] counts = {1, 4, 7, 8, 16, 20, 24, 36, 48, 64, 69, 72, 96, 128, 256, 512};
        byte[] ikm;
        byte[] salt;

        for (int i : counts) {
            ikm = RandomUtils.nextBytes(i);
            salt = RandomUtils.nextBytes(i * 2);
            checkLength(HKDF.extractHmacSha256(ikm, salt), 32);
            checkLength(HKDF.extractHmacSha256(ikm, null), 32);
            checkLength(HKDF.extractHmacSha256(ikm, new byte[0]), 32);
            checkLength(HKDF.extractHmacSha512(ikm, salt), 64);
            checkLength(HKDF.extractHmacSha512(ikm, null), 64);
            checkLength(HKDF.extract(HkdfMacFactory.Default.hmacSha1(), ikm, salt), 20);
            checkLength(HKDF.extract(new HkdfMacFactory.Default("HmacMd5", 16), ikm, salt), 16);
        }
    }

    private void checkLength(byte[] prk, int refOutLength) {
        assertEquals(refOutLength, prk.length);
    }

    @Test
    public void testExtractFailures() throws Exception {
        try {
            HKDF.extractHmacSha256(null, RandomUtils.nextBytes(10));
            fail();
        } catch (Exception e) {
        }

        try {
            HKDF.extractHmacSha512(new byte[0], null);
            fail();
        } catch (Exception e) {
        }
    }

    @Test
    public void testExpand() throws Exception {
        int[] lengthsPrk = {1, 16, 20, 32, 64};
        int[] lengthsOut = {1, 4, 7, 8, 16, 20, 24, 36, 48, 64, 69, 72, 96, 128, 256, 512};
        byte[] prk;
        byte[] info;
        for (int lengthPrk : lengthsPrk) {
            for (int lengthOut : lengthsOut) {
                prk = RandomUtils.nextBytes(lengthPrk);
                info = RandomUtils.nextBytes(lengthPrk);
                checkLength(HKDF.expandHmacSha256(prk, info, lengthOut), lengthOut);
                checkLength(HKDF.expandHmacSha256(prk, null, lengthOut), lengthOut);
                checkLength(HKDF.expandHmacSha256(prk, new byte[0], lengthOut), lengthOut);
                checkLength(HKDF.expandHmacSha512(prk, info, lengthOut), lengthOut);
                checkLength(HKDF.expandHmacSha512(prk, null, lengthOut), lengthOut);
                checkLength(HKDF.expand(HkdfMacFactory.Default.hmacSha1(), prk, info, lengthOut), lengthOut);
                checkLength(HKDF.expand(new HkdfMacFactory.Default("HmacMd5", 16), prk, info, lengthOut), lengthOut);
            }
        }
    }

    @Test
    public void testExpandFailures() throws Exception {
        try {
            HKDF.expandHmacSha256(null, RandomUtils.nextBytes(10), 16);
            fail();
        } catch (Exception e) {
        }

        try {
            HKDF.expandHmacSha256(RandomUtils.nextBytes(16), RandomUtils.nextBytes(8), 0);
            fail();
        } catch (Exception e) {
        }

        try {
            HKDF.expandHmacSha256(new byte[0], RandomUtils.nextBytes(8), 16);
            fail();
        } catch (Exception e) {
        }

        try {
            HKDF.expandHmacSha256(RandomUtils.nextBytes(16), RandomUtils.nextBytes(8), 256 * 32);
            fail();
        } catch (Exception e) {
        }
    }

    @Test
    public void hkdf() throws Exception {
        checkLength(HKDF.hkdf(HkdfMacFactory.Default.hmacSha1(), RandomUtils.nextBytes(16), RandomUtils.nextBytes(16), null, 80), 80);
        checkLength(HKDF.hkdfSha256(RandomUtils.nextBytes(16), RandomUtils.nextBytes(16), null, 80), 80);
    }

    @Test
    public void rfc5869testCase1() throws Exception {
        String PRK = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";

        checkStep1Sha256("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "000102030405060708090a0b0c", PRK);
        checkStep2Sha256(PRK,
                "f0f1f2f3f4f5f6f7f8f9", 42,
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    }


    @Test
    public void rfc5869testCase2() throws Exception {
        String PRK = "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244";

        checkStep1Sha256("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
                        "404142434445464748494a4b4c4d4e4f",
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
                        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
                        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                PRK);
        checkStep2Sha256(PRK, "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9" +
                "dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", 82, "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271c" +
                "b41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87");
    }

    @Test
    public void rfc5869testCase3() throws Exception {
        String IKM = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
        String salt = "";
        String info = "";
        int L = 42;
        String PRK = "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04";
        String OKM = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8";

        checkStep1Sha256(IKM, salt, PRK);
        checkStep2Sha256(PRK, info, L, OKM);
    }

    @Test
    public void rfc5869testCase4() throws Exception {
        String IKM = "0b0b0b0b0b0b0b0b0b0b0b";
        String salt = "000102030405060708090a0b0c";
        String info = "f0f1f2f3f4f5f6f7f8f9";
        int L = 42;
        String PRK = "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243";
        String OKM = "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896";

        checkStep1Sha1(IKM, salt, PRK);
        checkStep2Sha1(PRK, info, L, OKM);
    }

    @Test
    public void rfc5869testCase5() throws Exception {
        String IKM = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
                "404142434445464748494a4b4c4d4e4f";
        String salt = "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
        String info = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
                "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
        int L = 82;
        String PRK = "8adae09a2a307059478d309b26c4115a224cfaf6";
        String OKM = "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe" +
                "8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e" +
                "927336d0441f4c4300e2cff0d0900b52d3b4";

        checkStep1Sha1(IKM, salt, PRK);
        checkStep2Sha1(PRK, info, L, OKM);
    }

    @Test
    public void rfc5869testCase6() throws Exception {
        String IKM = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
        String salt = "";
        String info = "";
        int L = 42;
        String PRK = "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01";
        String OKM = "0ac1af7002b3d761d1e55298da9d0506" +
                "b9ae52057220a306e07b6b87e8df21d0" +
                "ea00033de03984d34918";

        checkStep1Sha1(IKM, salt, PRK);
        checkStep2Sha1(PRK, info, L, OKM);
    }

    @Test
    public void rfc5869testCase7() throws Exception {
        String IKM = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
        String salt = "";
        String info = "";
        int L = 42;
        String PRK = "2adccada18779e7c2077ad2eb19d3f3e731385dd";
        String OKM = "2c91117204d745f3500d636a62f64f0a" +
                "b3bae548aa53d423b0d1f27ebba6f5e5" +
                "673a081d70cce7acfc48";

        checkStep1Sha1(IKM, salt, PRK);
        checkStep2Sha1(PRK, info, L, OKM);
    }

    private void checkStep1Sha256(String ikm, String salt, String prk) throws Exception {
        checkStep1(HkdfMacFactory.Default.hmacSha256(), ikm, salt, prk);
    }

    private void checkStep2Sha256(String prk, String info, int l, String okm) throws Exception {
        checkStep2(HkdfMacFactory.Default.hmacSha256(), prk, info, l, okm);
    }

    private void checkStep1Sha1(String ikm, String salt, String prk) throws Exception {
        checkStep1(HkdfMacFactory.Default.hmacSha1(), ikm, salt, prk);
    }

    private void checkStep2Sha1(String prk, String info, int l, String okm) throws Exception {
        checkStep2(HkdfMacFactory.Default.hmacSha1(), prk, info, l, okm);
    }

    private void checkStep1(HkdfMacFactory macFactory, String ikm, String salt, String prk) throws Exception {
        byte[] currentPrk = HKDF.extract(macFactory, Hex.decodeHex(ikm.toCharArray()),
                Hex.decodeHex(salt.toCharArray()));
        assertArrayEquals(Hex.decodeHex(prk.toCharArray()), currentPrk);
    }

    private void checkStep2(HkdfMacFactory macFactory, String prk, String info, int l, String okm) throws Exception {
        byte[] currentOkm = HKDF.expand(macFactory, Hex.decodeHex(prk.toCharArray()),
                Hex.decodeHex(info.toCharArray()), l);
        assertArrayEquals(Hex.decodeHex(okm.toCharArray()), currentOkm);
    }
}