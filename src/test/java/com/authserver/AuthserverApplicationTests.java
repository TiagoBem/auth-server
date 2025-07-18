package com.authserver;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = {
    "jwt.secret=XIQJY+BbKQz701x3+ArZqT2xtPNyL/5NaXaiETV1j78=",
    "jwt.refresh.expiration=604800000"
})
class AuthserverApplicationTests {

	@Test
	void contextLoads() {
	}

}
