package com.microservices.resourceserver;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;

// import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import reactor.core.publisher.Mono;

@RestController
public class MeController {
    @GetMapping("/me")
    // @PreAuthorize("hasAuthority('NICE')")
    public Mono<UserInfoDto> getMe(Authentication auth) {
        if (auth instanceof JwtAuthenticationToken jwtAuth) {
            final var email = (String) jwtAuth.getTokenAttributes()
                    .getOrDefault(StandardClaimNames.EMAIL, "");
            final var roles = auth.getAuthorities()
                    .stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();
            final var exp = Optional.ofNullable(jwtAuth.getTokenAttributes()
                    .get(JwtClaimNames.EXP)).map(expClaim -> {
                        if (expClaim instanceof Long lexp) {
                            return lexp;
                        }
                        if (expClaim instanceof Instant iexp) {
                            return iexp.getEpochSecond();
                        }
                        if (expClaim instanceof Date dexp) {
                            return dexp.toInstant().getEpochSecond();
                        }
                        return Long.MAX_VALUE;
                    }).orElse(Long.MAX_VALUE);
            return Mono.just(new UserInfoDto(auth.getName(), email, roles, exp));
        }
        return Mono.just(UserInfoDto.ANONYMOUS);
    }

    @GetMapping("/greet")
    public Mono<MessageDto> getGreeting(Authentication auth) {
        return Mono.just(
                new MessageDto("Hi %s! You are granted with: %s.".formatted(auth.getName(), auth.getAuthorities())));
    }

    static record MessageDto(String body) {
    }

    /**
     * @param username a unique identifier for the resource owner in the token (sub
     *                 claim by default)
     * @param email    OpenID email claim
     * @param roles    Spring authorities resolved for the authentication in the
     *                 security context
     * @param exp      seconds from 1970-01-01T00:00:00Z UTC until the specified UTC
     *                 date/time when the access token expires
     */
    public static record UserInfoDto(String username, String email, List<String> roles, Long exp) {
        public static final UserInfoDto ANONYMOUS = new UserInfoDto("", "", List.of(), Long.MAX_VALUE);
    }
}
