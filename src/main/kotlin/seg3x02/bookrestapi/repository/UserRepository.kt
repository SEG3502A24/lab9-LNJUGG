package seg3x02.booksrestapi.repository

import org.springframework.data.repository.CrudRepository
import seg3x02.booksrestapi.security.credentials.User
import java.util.Optional

interface UserRepository : CrudRepository<User, Long> {

    fun findByUsername(username: String): Optional<User>
    fun existsByUsername(username: String): Boolean
}
