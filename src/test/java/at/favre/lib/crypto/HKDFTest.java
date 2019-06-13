package at.favre.lib.crypto;

import at.favre.lib.bytes.Bytes;
import org.apache.commons.lang3.RandomUtils;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.*;

public class HKDFTest {

    @Test
    public void quickStarTest() {
        byte[] lowEntropyInput = new byte[]{0x62, 0x58, (byte) 0x84, 0x2C};

        byte[] pseudoRandomKey = HKDF.fromHmacSha256().extract((SecretKey) null, lowEntropyInput);
        byte[] outputKeyingMaterial = HKDF.fromHmacSha256().expand(pseudoRandomKey, null, 64);

        assertEquals(64, outputKeyingMaterial.length);
    }

    @Test
    public void simpleUseCase() throws Exception {
        //if no dynamic salt is available, a static salt is better than null
        byte[] staticSalt32Byte = new byte[]{(byte) 0xDA, (byte) 0xAC, 0x3E, 0x10, 0x55, (byte) 0xB5, (byte) 0xF1, 0x3E, 0x53, (byte) 0xE4, 0x70, (byte) 0xA8, 0x77, 0x79, (byte) 0x8E, 0x0A, (byte)
                0x89, (byte) 0xAE, (byte) 0x96, 0x5F, 0x19, 0x5D, 0x53, 0x62, 0x58, (byte) 0x84, 0x2C, 0x09, (byte) 0xAD, 0x6E, 0x20, (byte) 0xD4};

        //example input
        byte[] sharedSecret = Bytes.random(256).array();

        HKDF hkdf = HKDF.fromHmacSha256();

        //extract the "raw" data to create output with concentrated entropy
        byte[] pseudoRandomKey = hkdf.extract(staticSalt32Byte, sharedSecret);

        //create expanded bytes for e.g. AES secret key and IV
        byte[] expandedAesKey = hkdf.expand(pseudoRandomKey, "aes-key".getBytes(StandardCharsets.UTF_8), 16);
        byte[] expandedIv = hkdf.expand(pseudoRandomKey, "aes-iv".getBytes(StandardCharsets.UTF_8), 16);

        //Example boilerplate encrypting a simple string with created key/iv
        SecretKey key = new SecretKeySpec(expandedAesKey, "AES"); //AES-128 key
        byte[] message = "my secret message".getBytes(StandardCharsets.UTF_8);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(expandedIv));
        byte[] encrypted = cipher.doFinal(message);

        assertNotNull(encrypted);
        assertTrue(encrypted.length > 0);

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(expandedIv));
        byte[] decrypted = cipher.doFinal(encrypted);

        assertArrayEquals(message, decrypted);
        assertFalse(Arrays.equals(encrypted, decrypted));
    }

    @Test
    public void customHmac() {
        //don't use md5, this is just an example
        HKDF hkdfMd5 = HKDF.from(new HkdfMacFactory.Default("HmacMD5", Security.getProvider("SunJCE")));

        byte[] lowEntropyInput = new byte[]{0x62, 0x58, (byte) 0x84, 0x2C};
        byte[] outputKeyingMaterial = hkdfMd5.extractAndExpand((SecretKey) null, lowEntropyInput, null, 32);

        assertEquals(32, outputKeyingMaterial.length);
    }

    @Test
    public void checkLength() {
        int[] counts = {1, 4, 7, 8, 16, 20, 24, 36, 48, 64, 69, 72, 96, 128, 256, 512};
        byte[] ikm;
        byte[] salt;

        for (int i : counts) {
            ikm = RandomUtils.nextBytes(i);
            salt = RandomUtils.nextBytes(i * 2);
            checkLength(HKDF.fromHmacSha256().extract(salt, ikm), 32);
            checkLength(HKDF.fromHmacSha256().extract((SecretKey) null, ikm), 32);
            checkLength(HKDF.fromHmacSha256().extract(new byte[0], ikm), 32);
            checkLength(HKDF.fromHmacSha512().extract(salt, ikm), 64);
            checkLength(HKDF.fromHmacSha512().extract((SecretKey) null, ikm), 64);
            checkLength(HKDF.from(HkdfMacFactory.Default.hmacSha1()).extract(salt, ikm), 20);
            checkLength(HKDF.from(new HkdfMacFactory.Default("HmacMD5")).extract(ikm, salt), 16);

            assertFalse(Arrays.equals(HKDF.fromHmacSha256().extract(salt, ikm), HKDF.fromHmacSha512().extract(salt, ikm)));
            assertFalse(Arrays.equals(HKDF.fromHmacSha256().extract(salt, ikm), HKDF.from(HkdfMacFactory.Default.hmacSha1()).extract(salt, ikm)));
        }
    }

    private void checkLength(byte[] prk, int refOutLength) {
        assertEquals(refOutLength, prk.length);
    }

    @Test
    public void testExtractFailures() {
        try {
            HKDF.fromHmacSha256().extract(RandomUtils.nextBytes(10), null);
            fail();
        } catch (Exception ignored) {
        }

        try {
            HKDF.fromHmacSha512().extract((SecretKey) null, new byte[0]);
            fail();
        } catch (Exception ignored) {
        }
    }

    @Test
    public void testSmallArrayInput() {
        byte[] b1 = HKDF.fromHmacSha256().extractAndExpand(new byte[16], new byte[]{1}, "smth".getBytes(), 64);
        byte[] b2 = HKDF.fromHmacSha256().extractAndExpand(new byte[16], new byte[]{1}, "smth".getBytes(), 64);
        byte[] b3 = HKDF.fromHmacSha256().extractAndExpand(new byte[16], new byte[1], "smth".getBytes(), 64);
        byte[] b4 = HKDF.fromHmacSha256().extractAndExpand(new byte[16], new byte[2], "smth".getBytes(), 64);

        assertArrayEquals(b1, b2);
        assertFalse(Arrays.equals(b1, b3));
        assertFalse(Arrays.equals(b1, b4));
        assertFalse(Arrays.equals(b3, b4));

        System.out.println(Bytes.wrap(b1).encodeHex());
        System.out.println(Bytes.wrap(b2).encodeHex());
        System.out.println(Bytes.wrap(b3).encodeHex());
        System.out.println(Bytes.wrap(b4).encodeHex());
    }

    @Test
    public void testExpand() {
        int[] lengthsPrk = {1, 16, 20, 32, 64};
        int[] lengthsOut = {1, 4, 7, 8, 16, 20, 24, 36, 48, 64, 69, 72, 96, 128, 256, 512};
        byte[] prk;
        byte[] info;
        for (int lengthPrk : lengthsPrk) {
            for (int lengthOut : lengthsOut) {
                prk = RandomUtils.nextBytes(lengthPrk);
                info = RandomUtils.nextBytes(lengthPrk);
                checkLength(HKDF.fromHmacSha256().expand(prk, info, lengthOut), lengthOut);
                checkLength(HKDF.fromHmacSha256().expand(prk, null, lengthOut), lengthOut);
                checkLength(HKDF.fromHmacSha256().expand(prk, new byte[0], lengthOut), lengthOut);
                checkLength(HKDF.fromHmacSha512().expand(prk, info, lengthOut), lengthOut);
                checkLength(HKDF.fromHmacSha512().expand(prk, null, lengthOut), lengthOut);
                checkLength(HKDF.from(HkdfMacFactory.Default.hmacSha1()).expand(prk, info, lengthOut), lengthOut);
                checkLength(HKDF.from(new HkdfMacFactory.Default("HmacMD5")).expand(prk, info, lengthOut), lengthOut);

                if (lengthOut > 4) {
                    assertFalse(Arrays.equals(HKDF.fromHmacSha256().expand(prk, info, lengthOut), HKDF.fromHmacSha512().expand(prk, info, lengthOut)));
                    assertFalse(Arrays.equals(HKDF.fromHmacSha256().expand(prk, info, lengthOut), HKDF.from(HkdfMacFactory.Default.hmacSha1()).expand(prk, info, lengthOut)));
                }
            }
        }
    }

    @Test
    public void testExpandFailures() {
        try {
            HKDF.fromHmacSha256().expand((SecretKey) null, RandomUtils.nextBytes(10), 16);
            fail();
        } catch (Exception ignored) {
        }

        try {
            HKDF.fromHmacSha256().expand(RandomUtils.nextBytes(16), RandomUtils.nextBytes(8), 0);
            fail();
        } catch (Exception ignored) {
        }

        try {
            HKDF.fromHmacSha256().expand(new byte[0], RandomUtils.nextBytes(8), 16);
            fail();
        } catch (Exception ignored) {
        }

        try {
            HKDF.fromHmacSha256().expand(RandomUtils.nextBytes(16), RandomUtils.nextBytes(8), 256 * 32);
            fail();
        } catch (Exception ignored) {
        }
    }

    @Test
    public void extractAndExpand() {
        checkLength(HKDF.from(HkdfMacFactory.Default.hmacSha1()).extractAndExpand(RandomUtils.nextBytes(20), RandomUtils.nextBytes(16), null, 80), 80);
        checkLength(HKDF.fromHmacSha256().extractAndExpand(RandomUtils.nextBytes(32), RandomUtils.nextBytes(16), null, 80), 80);
        checkLength(HKDF.fromHmacSha512().extractAndExpand(RandomUtils.nextBytes(64), RandomUtils.nextBytes(250), null, 80), 80);
    }

    @Test
    public void testLongInputExpand() {
        byte[] longInput = RandomUtils.nextBytes(1024 * 1024); //1 MiB
        checkLength(HKDF.fromHmacSha256().extract((SecretKey) null, longInput), 32);
    }

    @Test
    public void testLongOutputExtract() {
        int outLengthSha512 = 255 * 64;
        checkLength(HKDF.fromHmacSha512().expand(HKDF.fromHmacSha512().extract((SecretKey) null, new byte[16]), null, outLengthSha512), outLengthSha512);

        int outLengthSha256 = 255 * 32;
        checkLength(HKDF.fromHmacSha256().expand(HKDF.fromHmacSha256().extract((SecretKey) null, new byte[16]), null, outLengthSha256), outLengthSha256);
    }

    @Test
    public void multiThreadParallelTest() throws Exception {
        ExecutorService executorService = Executors.newFixedThreadPool(32);
        final HKDF hkdf = HKDF.fromHmacSha256();

        for (int i = 0; i < 512; i++) {
            executorService.submit(new Runnable() {
                @Override
                public void run() {
                    try {
                        Thread.sleep(2);

                        //System.out.println("[" + System.nanoTime() + "|" + Thread.currentThread().getName() + "] start thread");

                        Random r = new Random();

                        Thread.sleep(r.nextInt(5));

                        byte[] ikm = RandomUtils.nextBytes(r.nextInt(12) + 12);
                        byte[] salt = RandomUtils.nextBytes(r.nextInt(32));
                        byte[] prk = hkdf.extract(salt, ikm);

                        assertEquals(hkdf.getMacFactory().getMacLengthBytes(), prk.length);

                        //System.out.println("[" + System.nanoTime() + "|" + Thread.currentThread().getName() + "] prk: " + Hex.encodeHexString(prk));

                        Thread.sleep(r.nextInt(5));

                        int length = 16 + r.nextInt(80);
                        byte[] okm = hkdf.expand(prk, null, length);
                        //System.out.println("[" + System.nanoTime() + "|" + Thread.currentThread().getName() + "] okm: " + Hex.encodeHexString(okm));
                        assertEquals(okm.length, length);

                        System.out.println("[" + System.nanoTime() + "|" + Thread.currentThread().getName() + "] end thread");
                    } catch (Exception e) {
                        fail(e.getMessage());
                    }
                }
            });
        }
        executorService.shutdown();
        executorService.awaitTermination(10, TimeUnit.SECONDS);
    }

    @Test
    public void testSecretKeyApis() {
        byte[] salt = Bytes.random(16).array();
        byte[] ikm = Bytes.random(16).array();
        HkdfMacFactory hkdfMacFactory = HkdfMacFactory.Default.hmacSha256();
        HKDF hkdf = HKDF.from(hkdfMacFactory);

        // extract

        byte[] prkSk = hkdf.extract(hkdfMacFactory.createSecretKey(salt), ikm);
        byte[] prkBa = hkdf.extract(salt, ikm);

        assertArrayEquals(prkSk, prkBa);

        // expand with and without info

        byte[] okmSk = hkdf.expand(hkdfMacFactory.createSecretKey(prkSk), new byte[4], 511);
        byte[] okmBa = hkdf.expand(prkSk, new byte[4], 511);

        assertArrayEquals(okmSk, okmBa);

        byte[] okmSk2 = hkdf.expand(hkdfMacFactory.createSecretKey(prkSk), null, 213);
        byte[] okmBa2 = hkdf.expand(prkSk, null, 213);

        assertArrayEquals(okmSk2, okmBa2);

        // extract and expand

        assertArrayEquals(
                hkdf.extractAndExpand(hkdfMacFactory.createSecretKey(salt), ikm, new byte[4], 31),
                hkdf.extractAndExpand(salt, ikm, new byte[4], 31)
        );
    }

    @Test
    public void testWithNullSalt() {
        byte[] prkSk = HKDF.fromHmacSha256().extract((SecretKey) null, Bytes.random(16).array());
        assertNotNull(prkSk);
    }
}
