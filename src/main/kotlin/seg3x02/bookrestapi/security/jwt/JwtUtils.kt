package seg3x02.booksrestapi.security.jwt

import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.JwtEncoderParameters
import org.springframework.stereotype.Service
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.stream.Collectors

@Service
class JwtUtils(private val encoder: JwtEncoder) {

    fun generateJwtToken(authentication: Authentication): String {
        val now = Instant.now()

        // Construire le scope en concaténant les autorités
        val scope: String = authentication.authorities.stream()
            .map { authority: GrantedAuthority -> authority.authority }
            .collect(Collectors.joining(" "))

        // Construire le payload des claims du JWT
        val claims = JwtClaimsSet.builder()
            .issuer("self")
            .issuedAt(now)
            .expiresAt(now.plus(1, ChronoUnit.HOURS)) // Expiration dans 1 heure
            .subject(authentication.name)
            .claim("scope", scope)
            .build()

        // Encoder le token avec les claims
        return encoder.encode(JwtEncoderParameters.from(claims)).tokenValue
    }
}
