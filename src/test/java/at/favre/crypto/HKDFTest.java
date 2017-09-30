package at.favre.crypto;

import org.apache.commons.lang3.RandomUtils;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class HKDFTest {
    @Before
    public void setUp() throws Exception {
    }

    @Test
    public void testLength() throws Exception {
        int[] counts = {1, 4, 7, 8, 16, 20, 24, 36, 48, 64, 69, 72, 96, 128, 256, 512};
        byte[] ikm;
        byte[] salt;

        for (int i : counts) {
            ikm = RandomUtils.nextBytes(i);
            salt = RandomUtils.nextBytes(i * 2);
            testLength(HKDF.extractHmacSha256(ikm, salt), 32);
            testLength(HKDF.extractHmacSha256(ikm, null), 32);
            testLength(HKDF.extractHmacSha512(ikm, salt), 64);
            testLength(HKDF.extractHmacSha512(ikm, null), 64);
            testLength(HKDF.extract(new HkdfMacFactory.Default("HmacSha1", 20), ikm, salt), 20);
        }
    }

    private void testLength(byte[] prk, int refOutLength) {
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
                testLength(HKDF.expandHmacSha256(prk, info, lengthOut), lengthOut);
                testLength(HKDF.expandHmacSha256(prk, null, lengthOut), lengthOut);
                testLength(HKDF.expandHmacSha512(prk, info, lengthOut), lengthOut);
                testLength(HKDF.expandHmacSha512(prk, null, lengthOut), lengthOut);
                testLength(HKDF.expand(new HkdfMacFactory.Default("HmacSha1", 20), prk, info, lengthOut), lengthOut);
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
    }

    @Test
    public void hkdf() throws Exception {
    }

}