package at.favre.lib.crypto;

import org.junit.Test;

import javax.crypto.Mac;
import java.security.Security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class HkdfMacFactoryTest {
    @Test
    public void hmacSha256() throws Exception {
        testHmacFactory(HkdfMacFactory.Default.hmacSha256(), 32);
    }

    @Test
    public void hmacSha512() throws Exception {
        testHmacFactory(HkdfMacFactory.Default.hmacSha512(), 64);
    }

    @Test
    public void hmacSha1() throws Exception {
        testHmacFactory(HkdfMacFactory.Default.hmacSha1(), 20);
    }

    @Test
    public void hmacMd5() throws Exception {
        testHmacFactory(new HkdfMacFactory.Default("HmacMD5"), 16);
    }

    @Test
    public void customProvider() throws Exception {
        testHmacFactory(new HkdfMacFactory.Default("HmacSHA1", Security.getProvider("SunJCE")), 20);
    }

    @Test(expected = RuntimeException.class)
    public void hmacInstanceNotExisting() throws Exception {
        new HkdfMacFactory.Default("HmacNotExisting", null).createInstance(new byte[16]);
    }

    @Test(expected = RuntimeException.class)
    public void hmacUsingEmptyKey() throws Exception {
        HkdfMacFactory.Default.hmacSha256().createInstance(new byte[0]);
    }

    private void testHmacFactory(HkdfMacFactory macFactory, int refLength) {
        Mac mac = macFactory.createInstance(new byte[refLength]);
        assertNotNull(mac);

        mac.update(new byte[]{0x76, (byte) 0x92, 0x0E, 0x5E, (byte) 0x85, (byte) 0xDB, (byte) 0xA7, (byte) 0x8F});
        byte[] hash = mac.doFinal();
        assertEquals(refLength, hash.length);
    }
}
