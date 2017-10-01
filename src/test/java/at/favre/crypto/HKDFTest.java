package at.favre.crypto;

import org.apache.commons.lang3.RandomUtils;
import org.junit.Before;
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
    @Before
    public void setUp() throws Exception {
    }

    @Test
    public void quickStarTest() throws Exception {
        byte[] lowEntropyInput = new byte[]{0x62, 0x58, (byte) 0x84, 0x2C};

        byte[] pseudoRandomKey = HKDF.fromHmacSha256().extract(lowEntropyInput, null);
        byte[] outputKeyingMaterial = HKDF.fromHmacSha256().expand(pseudoRandomKey, null, 64);

        assertEquals(64, outputKeyingMaterial.length);
    }

    @Test
    public void simpleUseCase() throws Exception {
        //if no dynamic salt is available, a static salt is better than null
        byte[] staticSalt32Byte = new byte[]{(byte) 0xDA, (byte) 0xAC, 0x3E, 0x10, 0x55, (byte) 0xB5, (byte) 0xF1, 0x3E, 0x53, (byte) 0xE4, 0x70, (byte) 0xA8, 0x77, 0x79, (byte) 0x8E, 0x0A, (byte) 0x89, (byte) 0xAE, (byte) 0x96, 0x5F, 0x19, 0x5D, 0x53, 0x62, 0x58, (byte) 0x84, 0x2C, 0x09, (byte) 0xAD, 0x6E, 0x20, (byte) 0xD4};

        //example input
        String userInput = "this is a user input with bad entropy";

        HKDF hkdf = HKDF.fromHmacSha256();

        //extract the "raw" data to create output with concentrated entropy
        byte[] pseudoRandomKey = hkdf.extract(userInput.getBytes(StandardCharsets.UTF_8), staticSalt32Byte);

        //create expanded bytes for e.g. AES secret key and IV
        byte[] expandedAesKey = hkdf.expand(pseudoRandomKey, "aes-key".getBytes(StandardCharsets.UTF_8), 16);
        byte[] expandedIv = hkdf.expand(pseudoRandomKey, "aes-iv".getBytes(StandardCharsets.UTF_8), 16);

        //Example boilerplate encrypting a simple string with created key/iv
        SecretKey key = new SecretKeySpec(expandedAesKey, "AES"); //AES-128 key
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(expandedIv));
        byte[] encrypted = cipher.doFinal("my secret message".getBytes(StandardCharsets.UTF_8));

        assertNotNull(encrypted);
        assertTrue(encrypted.length > 0);
    }

    @Test
    public void customHmac() throws Exception {
        //don't use md5, this is just an example
        HKDF hkdfMd5 = HKDF.from(new HkdfMacFactory.Default("HmacMD5", 16, Security.getProvider("SunJCE")));

        byte[] lowEntropyInput = new byte[]{0x62, 0x58, (byte) 0x84, 0x2C};
        byte[] outputKeyingMaterial = hkdfMd5.extractAndExpand(lowEntropyInput, null, null, 32);

        assertEquals(32, outputKeyingMaterial.length);
    }

    @Test
    public void checkLength() throws Exception {
        int[] counts = {1, 4, 7, 8, 16, 20, 24, 36, 48, 64, 69, 72, 96, 128, 256, 512};
        byte[] ikm;
        byte[] salt;

        for (int i : counts) {
            ikm = RandomUtils.nextBytes(i);
            salt = RandomUtils.nextBytes(i * 2);
            checkLength(HKDF.fromHmacSha256().extract(ikm, salt), 32);
            checkLength(HKDF.fromHmacSha256().extract(ikm, null), 32);
            checkLength(HKDF.fromHmacSha256().extract(ikm, new byte[0]), 32);
            checkLength(HKDF.fromHmacSha512().extract(ikm, salt), 64);
            checkLength(HKDF.fromHmacSha512().extract(ikm, null), 64);
            checkLength(HKDF.from(HkdfMacFactory.Default.hmacSha1()).extract(ikm, salt), 20);
            checkLength(HKDF.from(new HkdfMacFactory.Default("HmacMD5", 16)).extract(ikm, salt), 16);

            assertFalse(Arrays.equals(HKDF.fromHmacSha256().extract(ikm, salt), HKDF.fromHmacSha512().extract(ikm, salt)));
            assertFalse(Arrays.equals(HKDF.fromHmacSha256().extract(ikm, salt), HKDF.from(HkdfMacFactory.Default.hmacSha1()).extract(ikm, salt)));
        }
    }

    private void checkLength(byte[] prk, int refOutLength) {
        assertEquals(refOutLength, prk.length);
    }

    @Test
    public void testExtractFailures() throws Exception {
        try {
            HKDF.fromHmacSha256().extract(null, RandomUtils.nextBytes(10));
            fail();
        } catch (Exception ignored) {
        }

        try {
            HKDF.fromHmacSha512().extract(new byte[0], null);
            fail();
        } catch (Exception ignored) {
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
                checkLength(HKDF.fromHmacSha256().expand(prk, info, lengthOut), lengthOut);
                checkLength(HKDF.fromHmacSha256().expand(prk, null, lengthOut), lengthOut);
                checkLength(HKDF.fromHmacSha256().expand(prk, new byte[0], lengthOut), lengthOut);
                checkLength(HKDF.fromHmacSha512().expand(prk, info, lengthOut), lengthOut);
                checkLength(HKDF.fromHmacSha512().expand(prk, null, lengthOut), lengthOut);
                checkLength(HKDF.from(HkdfMacFactory.Default.hmacSha1()).expand(prk, info, lengthOut), lengthOut);
                checkLength(HKDF.from(new HkdfMacFactory.Default("HmacMD5", 16)).expand(prk, info, lengthOut), lengthOut);

                if (lengthOut > 4) {
                    assertFalse(Arrays.equals(HKDF.fromHmacSha256().expand(prk, info, lengthOut), HKDF.fromHmacSha512().expand(prk, info, lengthOut)));
                    assertFalse(Arrays.equals(HKDF.fromHmacSha256().expand(prk, info, lengthOut), HKDF.from(HkdfMacFactory.Default.hmacSha1()).expand(prk, info, lengthOut)));
                }
            }
        }
    }

    @Test
    public void testExpandFailures() throws Exception {
        try {
            HKDF.fromHmacSha256().expand(null, RandomUtils.nextBytes(10), 16);
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
    public void extractAndExpand() throws Exception {
        checkLength(HKDF.from(HkdfMacFactory.Default.hmacSha1()).extractAndExpand(RandomUtils.nextBytes(16), RandomUtils.nextBytes(20), null, 80), 80);
        checkLength(HKDF.fromHmacSha256().extractAndExpand(RandomUtils.nextBytes(16), RandomUtils.nextBytes(32), null, 80), 80);
        checkLength(HKDF.fromHmacSha512().extractAndExpand(RandomUtils.nextBytes(250), RandomUtils.nextBytes(64), null, 80), 80);
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
                        byte[] prk = hkdf.extract(ikm, salt);

                        assertTrue(hkdf.getMacFactory().macHashLengthByte() == prk.length);

                        //System.out.println("[" + System.nanoTime() + "|" + Thread.currentThread().getName() + "] prk: " + Hex.encodeHexString(prk));

                        Thread.sleep(r.nextInt(5));

                        int length = 16 + r.nextInt(80);
                        byte[] okm = hkdf.expand(prk, null, length);
                        //System.out.println("[" + System.nanoTime() + "|" + Thread.currentThread().getName() + "] okm: " + Hex.encodeHexString(okm));
                        assertTrue(okm.length == length);

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

}