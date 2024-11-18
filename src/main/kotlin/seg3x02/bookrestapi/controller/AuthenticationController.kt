package seg3x02.booksrestapi.controller

import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.bind.annotation.*
import seg3x02.booksrestapi.controller.payload.AuthResponse
import seg3x02.booksrestapi.controller.payload.MessageResponse
import seg3x02.booksrestapi.controller.payload.SignInData
import seg3x02.booksrestapi.controller.payload.SignUpData
import seg3x02.booksrestapi.repository.UserRepository
import seg3x02.booksrestapi.security.UserDetailsImpl
import seg3x02.booksrestapi.security.credentials.ERole
import seg3x02.booksrestapi.security.credentials.User
import seg3x02.booksrestapi.security.jwt.JwtUtils
import javax.validation.Valid

@RestController
@CrossOrigin(origins = ["http://localhost:4200"])
@RequestMapping("/auth")
class AuthenticationController(
    private val authenticationManager: AuthenticationManager,
    private val userRepository: UserRepository,
    private val encoder: PasswordEncoder,
    private val jwtUtils: JwtUtils
) {

    @PostMapping("/signin")
    fun authenticateUser(@Valid @RequestBody loginRequest: SignInData): ResponseEntity<*> {
        val authentication: Authentication = authenticationManager.authenticate(
            UsernamePasswordAuthenticationToken(loginRequest.username, loginRequest.password)
        )
        SecurityContextHolder.getContext().authentication = authentication

        val jwt = jwtUtils.generateJwtToken(authentication)
        val userDetails = authentication.principal as UserDetailsImpl
        val role = userDetails.authorities.elementAtOrNull(0)?.authority

        return ResponseEntity.ok(
            AuthResponse(
                token = jwt,
                id = userDetails.id,
                username = userDetails.username,
                role = role ?: "UNKNOWN"
            )
        )
    }

    @PostMapping("/signup")
    fun registerUser(@Valid @RequestBody signUpRequest: SignUpData): ResponseEntity<*> {
        if (userRepository.existsByUsername(signUpRequest.username)) {
            return ResponseEntity.badRequest().body(
                MessageResponse("Error: Username is already taken!")
            )
        }

        val user = User(
            username = signUpRequest.username,
            password = encoder.encode(signUpRequest.password)
        ).apply {
            role = if (signUpRequest.role.equals("admin", ignoreCase = true)) {
                ERole.ROLE_ADMIN
            } else {
                ERole.ROLE_USER
            }
        }

        userRepository.save(user)
        return ResponseEntity.ok(MessageResponse("User registered successfully!"))
    }
}
