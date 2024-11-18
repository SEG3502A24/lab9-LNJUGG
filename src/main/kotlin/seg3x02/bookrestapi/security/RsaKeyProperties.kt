package seg3x02.booksrestapi.security

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Configuration
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

@Configuration
@ConfigurationProperties(prefix = "rsa")
data class RsaKeyProperties(
    val publicKey: RSAPublicKey,
    val privateKey: RSAPrivateKey
)
