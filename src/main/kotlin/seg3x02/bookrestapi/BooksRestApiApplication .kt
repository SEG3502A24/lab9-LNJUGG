package seg3x02.booksrestapi

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication
import seg3x02.booksrestapi.security.RsaKeyProperties

@SpringBootApplication
@EnableConfigurationProperties(RsaKeyProperties::class)
class BooksRestApiApplication

fun main(args: Array<String>) {
    runApplication<BooksRestApiApplication>(*args)
}
