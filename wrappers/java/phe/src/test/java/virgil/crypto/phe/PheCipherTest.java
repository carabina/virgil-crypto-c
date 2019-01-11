package virgil.crypto.phe;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.nio.charset.StandardCharsets;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class PheCipherTest {

	private PheCipher cipher;

	@Before
	public void setup() {
		this.cipher = new PheCipher();
	}

	@After
	public void teardown() {
		this.cipher.close();
	}

	@Test
	public void testFullFlowShouldSucceed() {
		byte[] plainText = "plain text".getBytes(StandardCharsets.UTF_8);
		byte[] accountKey = "Gjg-Ap7Qa5BjpuZ22FhZsairw^ZS5KjC".getBytes(StandardCharsets.UTF_8); // 32 bytes string

		assertEquals(32, accountKey.length);

		this.cipher.setupDefaults();

		byte[] encryptedData = this.cipher.encrypt(plainText, accountKey);
		byte[] decryptedData = this.cipher.decrypt(encryptedData, accountKey);

		assertArrayEquals(plainText, decryptedData);
	}

}
