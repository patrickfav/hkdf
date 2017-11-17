package at.favre.lib.crypto;

import org.apache.commons.lang3.RandomUtils;
import org.junit.Ignore;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertTrue;

public class HKDFBenchmarkTest {

//    i7-7700k, 16GB DDR4, Java 8.131
//    count: 2042
//    Run (0): 3873013044ns
//    Run (1): 3602475691ns
//    Run (2): 3602419370ns
//    Run (3): 3613280596ns
//    Run (4): 3609781686ns

    @Ignore
    @Test
    public void benchmark() throws Exception {

        Map<Integer, Long> runsMap = new HashMap<>();

        int rounds = 5;
        byte[] input;
        for (int i = 0; i < rounds; i++) {
            int count = 0;
            long start = System.nanoTime();

            //benchmark different input sizes
            for (int j = 1024; j < 1024 * 1024; j += 1024) {
                input = RandomUtils.nextBytes(j);
                byte[] pseudoRandomKey = HKDF.fromHmacSha256().extract(new byte[]{0x62, 0x58, (byte) 0x84, 0x2C}, input);
                byte[] outputKeyingMaterial = HKDF.fromHmacSha256().expand(pseudoRandomKey, null, 32);
                assertTrue(outputKeyingMaterial.length > 0);
                count++;
            }

            //benchmark different input sizes
            for (int j = 16; j < 255 * 64; j += 16) {
                input = RandomUtils.nextBytes(128);
                byte[] pseudoRandomKey = HKDF.fromHmacSha512().extract(new byte[]{0x62, 0x58, (byte) 0x84, 0x2C}, input);
                byte[] outputKeyingMaterial = HKDF.fromHmacSha512().expand(pseudoRandomKey, null, j);
                assertTrue(outputKeyingMaterial.length > 0);
                count++;
            }

            runsMap.put(i, System.nanoTime() - start);
            System.out.println("count (" + i + "):" + count);
        }

        for (Map.Entry<Integer, Long> entry : runsMap.entrySet()) {
            System.out.println("Run (" + entry.getKey() + "): " + entry.getValue() + "ns");
        }
    }
}
